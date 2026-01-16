// ============================================================================
// SENTINELA - Servidor Express Principal
// ============================================================================

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { z } from 'zod';

import { env } from './config/env';
import { prisma } from './config/prisma';
import { autenticar, exigirPerfil } from './middleware/auth';
import { gerarTokenAcesso, gerarTokenRefresh } from './auth/jwt';
import { hashSenha, verificarSenha } from './utils/password';
import { sha256Hex } from './utils/crypto';
import { salvarChaveApi, listarChavesApi, removerChaveApi, PROVEDORES_INFO } from './services/chaveApiService';
import { obterResumoExecucoes } from './services/execucaoFonteService';
import { StatusVarredura, NivelRisco, ProvedorApi, PerfilUsuario } from '@prisma/client';

const app = express();

// Middlewares globais
app.use(helmet());
app.use(cors({ origin: env.FRONTEND_URL, credentials: true }));
app.use(compression());
app.use(express.json({ limit: '10mb' }));

// ============================================================================
// ROTAS PÚBLICAS - Autenticação
// ============================================================================

app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const schema = z.object({
      email: z.string().email(),
      senha: z.string().min(6),
    });
    
    const { email, senha } = schema.parse(req.body);
    
    const usuario = await prisma.usuario.findUnique({
      where: { email },
      include: {
        membros: {
          include: { organizacao: true },
          take: 1,
        },
      },
    });
    
    if (!usuario || !usuario.ativo) {
      res.status(401).json({ erro: 'Credenciais inválidas' });
      return;
    }
    
    const senhaValida = await verificarSenha(senha, usuario.senhaHash);
    if (!senhaValida) {
      res.status(401).json({ erro: 'Credenciais inválidas' });
      return;
    }
    
    const membro = usuario.membros[0];
    if (!membro) {
      res.status(401).json({ erro: 'Usuário não pertence a nenhuma organização' });
      return;
    }
    
    // Atualizar último acesso
    await prisma.usuario.update({
      where: { id: usuario.id },
      data: { ultimoAcessoEm: new Date() },
    });
    
    const tokenAcesso = gerarTokenAcesso({
      sub: usuario.id,
      email: usuario.email,
      organizacaoId: membro.organizacaoId,
      perfil: membro.perfil,
    });
    
    const tokenRefresh = gerarTokenRefresh(usuario.id);
    
    // Salvar refresh token
    await prisma.tokenRefresh.create({
      data: {
        usuarioId: usuario.id,
        tokenHash: sha256Hex(tokenRefresh),
        expiraEm: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
    
    res.json({
      tokenAcesso,
      tokenRefresh,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        perfil: membro.perfil,
        organizacao: {
          id: membro.organizacao.id,
          nome: membro.organizacao.nome,
        },
      },
    });
  } catch (erro: any) {
    res.status(400).json({ erro: erro.message });
  }
});

// ============================================================================
// ROTAS PROTEGIDAS
// ============================================================================

// ---------- Dashboard ----------

app.get('/api/dashboard', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const agora = new Date();
    const trintaDiasAtras = new Date(agora.getTime() - 30 * 24 * 60 * 60 * 1000);
    
    // Estatísticas gerais
    const [
      totalEmpresas,
      empresasMonitoradas,
      varredurasRecentes,
      totalAchados,
      achadosCriticos,
      achadosAltos,
    ] = await Promise.all([
      prisma.empresa.count({ where: { organizacaoId: orgId, ativa: true } }),
      prisma.monitoramentoEmpresa.count({ where: { empresa: { organizacaoId: orgId }, ativo: true } }),
      prisma.varredura.count({ where: { empresa: { organizacaoId: orgId }, criadoEm: { gte: trintaDiasAtras } } }),
      prisma.definicaoAchado.count({ where: { organizacaoId: orgId } }),
      prisma.definicaoAchado.count({ where: { organizacaoId: orgId, nivelRisco: NivelRisco.CRITICO, status: 'ABERTO' } }),
      prisma.definicaoAchado.count({ where: { organizacaoId: orgId, nivelRisco: NivelRisco.ALTO, status: 'ABERTO' } }),
    ]);
    
    // Últimas varreduras
    const ultimasVarreduras = await prisma.varredura.findMany({
      where: { empresa: { organizacaoId: orgId } },
      orderBy: { criadoEm: 'desc' },
      take: 5,
      include: { empresa: { select: { nome: true } } },
    });
    
    // Últimos achados
    const ultimosAchados = await prisma.definicaoAchado.findMany({
      where: { organizacaoId: orgId },
      orderBy: { ultimaVezEm: 'desc' },
      take: 10,
      include: {
        ocorrencias: {
          take: 1,
          include: { varredura: { include: { empresa: { select: { nome: true } } } } },
        },
      },
    });
    
    // Distribuição por nível de risco
    const distribuicaoPorRisco = await prisma.definicaoAchado.groupBy({
      by: ['nivelRisco'],
      where: { organizacaoId: orgId, status: 'ABERTO' },
      _count: true,
    });
    
    // Distribuição por fonte
    const distribuicaoPorFonte = await prisma.definicaoAchado.groupBy({
      by: ['fonte'],
      where: { organizacaoId: orgId },
      _count: true,
    });
    
    res.json({
      estatisticas: {
        totalEmpresas,
        empresasMonitoradas,
        varredurasUltimos30Dias: varredurasRecentes,
        totalAchados,
        achadosCriticos,
        achadosAltos,
      },
      ultimasVarreduras: ultimasVarreduras.map(v => ({
        id: v.id,
        empresa: v.empresa.nome,
        status: v.status,
        totalAchados: v.totalAchados,
        achadosCriticos: v.achadosCriticos,
        criadoEm: v.criadoEm,
      })),
      ultimosAchados: ultimosAchados.map(a => ({
        id: a.id,
        titulo: a.titulo,
        nivelRisco: a.nivelRisco,
        fonte: a.fonte,
        empresa: a.ocorrencias[0]?.varredura?.empresa?.nome || 'N/A',
        ultimaVezEm: a.ultimaVezEm,
      })),
      distribuicaoPorRisco: Object.fromEntries(
        distribuicaoPorRisco.map(d => [d.nivelRisco, d._count])
      ),
      distribuicaoPorFonte: Object.fromEntries(
        distribuicaoPorFonte.map(d => [d.fonte, d._count])
      ),
    });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

// ---------- Empresas ----------

app.get('/api/empresas', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const { busca, pagina = '1', limite = '20' } = req.query;
    
    const where: any = { organizacaoId: orgId };
    if (busca) {
      where.OR = [
        { nome: { contains: String(busca), mode: 'insensitive' } },
        { cnpj: { contains: String(busca) } },
        { dominios: { some: { dominio: { contains: String(busca), mode: 'insensitive' } } } },
      ];
    }
    
    const [empresas, total] = await Promise.all([
      prisma.empresa.findMany({
        where,
        include: {
          dominios: true,
          monitoramento: true,
          _count: { select: { varreduras: true } },
        },
        orderBy: { nome: 'asc' },
        skip: (Number(pagina) - 1) * Number(limite),
        take: Number(limite),
      }),
      prisma.empresa.count({ where }),
    ]);
    
    res.json({
      empresas: empresas.map(e => ({
        id: e.id,
        nome: e.nome,
        nomeFantasia: e.nomeFantasia,
        cnpj: e.cnpj,
        setor: e.setor,
        dominios: e.dominios.map(d => d.dominio),
        ativa: e.ativa,
        monitorada: e.monitoramento?.ativo ?? false,
        totalVarreduras: e._count.varreduras,
        criadoEm: e.criadoEm,
      })),
      total,
      paginas: Math.ceil(total / Number(limite)),
    });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

app.post('/api/empresas', autenticar, exigirPerfil('ADMINISTRADOR', 'ANALISTA'), async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const userId = req.usuario!.id;
    
    const schema = z.object({
      nome: z.string().min(2),
      nomeFantasia: z.string().optional(),
      cnpj: z.string().optional(),
      setor: z.string().optional(),
      dominios: z.array(z.string()).min(1),
      emailPrincipal: z.string().email().optional(),
    });
    
    const dados = schema.parse(req.body);
    
    const empresa = await prisma.empresa.create({
      data: {
        organizacaoId: orgId,
        nome: dados.nome,
        nomeFantasia: dados.nomeFantasia,
        cnpj: dados.cnpj,
        setor: dados.setor,
        emailPrincipal: dados.emailPrincipal,
        criadoPorId: userId,
        dominios: {
          create: dados.dominios.map((d, i) => ({
            dominio: d.toLowerCase().trim(),
            principal: i === 0,
          })),
        },
      },
      include: { dominios: true },
    });
    
    res.status(201).json({ empresa });
  } catch (erro: any) {
    res.status(400).json({ erro: erro.message });
  }
});

app.get('/api/empresas/:id', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const empresa = await prisma.empresa.findFirst({
      where: { id: req.params.id, organizacaoId: orgId },
      include: {
        dominios: true,
        monitoramento: true,
        varreduras: {
          orderBy: { criadoEm: 'desc' },
          take: 10,
        },
      },
    });
    
    if (!empresa) {
      res.status(404).json({ erro: 'Empresa não encontrada' });
      return;
    }
    
    res.json({ empresa });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

// ---------- Varreduras ----------

app.get('/api/varreduras', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const { empresaId, status, pagina = '1', limite = '20' } = req.query;
    
    const where: any = { empresa: { organizacaoId: orgId } };
    if (empresaId) where.empresaId = String(empresaId);
    if (status) where.status = String(status);
    
    const [varreduras, total] = await Promise.all([
      prisma.varredura.findMany({
        where,
        include: {
          empresa: { select: { id: true, nome: true } },
          criadoPor: { select: { nome: true } },
        },
        orderBy: { criadoEm: 'desc' },
        skip: (Number(pagina) - 1) * Number(limite),
        take: Number(limite),
      }),
      prisma.varredura.count({ where }),
    ]);
    
    res.json({
      varreduras: varreduras.map(v => ({
        id: v.id,
        empresa: v.empresa,
        status: v.status,
        escopo: v.escopo,
        totalAchados: v.totalAchados,
        achadosCriticos: v.achadosCriticos,
        achadosAltos: v.achadosAltos,
        criadoPor: v.criadoPor?.nome,
        criadoEm: v.criadoEm,
        iniciadaEm: v.iniciadaEm,
        concluidaEm: v.concluidaEm,
      })),
      total,
      paginas: Math.ceil(total / Number(limite)),
    });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

app.post('/api/varreduras', autenticar, exigirPerfil('ADMINISTRADOR', 'ANALISTA'), async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const userId = req.usuario!.id;
    
    const schema = z.object({
      empresaId: z.string().uuid(),
      escopo: z.enum(['DOMINIO', 'COMPLETO']).default('DOMINIO'),
      dominiosAdicionais: z.array(z.string()).optional(),
      emailsAdicionais: z.array(z.string()).optional(),
      varreduraProfunda: z.boolean().default(true),
    });
    
    const dados = schema.parse(req.body);
    
    // Verificar se empresa pertence à organização
    const empresa = await prisma.empresa.findFirst({
      where: { id: dados.empresaId, organizacaoId: orgId },
      include: { dominios: true },
    });
    
    if (!empresa) {
      res.status(404).json({ erro: 'Empresa não encontrada' });
      return;
    }
    
    const dominios = empresa.dominios.map(d => d.dominio);
    if (dados.dominiosAdicionais) {
      dominios.push(...dados.dominiosAdicionais);
    }
    
    const varredura = await prisma.varredura.create({
      data: {
        empresaId: dados.empresaId,
        criadoPorId: userId,
        escopo: dados.escopo,
        dadosEntrada: {
          dominios,
          emails: dados.emailsAdicionais || [],
          varreduraProfunda: dados.varreduraProfunda,
        },
      },
    });
    
    // TODO: Adicionar à fila de processamento
    // await filaVarreduras.add('executar', { varreduraId: varredura.id });
    
    res.status(201).json({ varredura });
  } catch (erro: any) {
    res.status(400).json({ erro: erro.message });
  }
});

app.get('/api/varreduras/:id', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const varredura = await prisma.varredura.findFirst({
      where: { id: req.params.id, empresa: { organizacaoId: orgId } },
      include: {
        empresa: { select: { id: true, nome: true, dominios: true } },
        criadoPor: { select: { nome: true, email: true } },
        execucoesFonte: {
          orderBy: { iniciadaEm: 'asc' },
        },
        ocorrenciasAchado: {
          include: {
            definicao: true,
          },
        },
        relatorio: true,
      },
    });
    
    if (!varredura) {
      res.status(404).json({ erro: 'Varredura não encontrada' });
      return;
    }
    
    // Resumo das execuções
    const resumoExecucoes = await obterResumoExecucoes(varredura.id);
    
    res.json({
      varredura: {
        id: varredura.id,
        empresa: varredura.empresa,
        status: varredura.status,
        escopo: varredura.escopo,
        dadosEntrada: varredura.dadosEntrada,
        totalAchados: varredura.totalAchados,
        achadosCriticos: varredura.achadosCriticos,
        achadosAltos: varredura.achadosAltos,
        achadosMedios: varredura.achadosMedios,
        achadosBaixos: varredura.achadosBaixos,
        criadoPor: varredura.criadoPor,
        criadoEm: varredura.criadoEm,
        iniciadaEm: varredura.iniciadaEm,
        concluidaEm: varredura.concluidaEm,
        mensagemErro: varredura.mensagemErro,
        relatorio: varredura.relatorio ? {
          id: varredura.relatorio.id,
          hashSha256: varredura.relatorio.hashSha256,
          criadoEm: varredura.relatorio.criadoEm,
        } : null,
      },
      execucoesFonte: resumoExecucoes.execucoes,
      resumoExecucoes: resumoExecucoes.resumo,
      achados: varredura.ocorrenciasAchado.map(o => ({
        id: o.definicao.id,
        titulo: o.definicao.titulo,
        descricao: o.definicao.descricao,
        recomendacao: o.definicao.recomendacao,
        nivelRisco: o.definicao.nivelRisco,
        fonte: o.definicao.fonte,
        tipo: o.definicao.tipo,
        tipoEntidade: o.definicao.tipoEntidade,
        entidade: o.definicao.entidade,
        status: o.definicao.status,
        evidencia: o.definicao.evidencia,
        primeiraVezEm: o.definicao.primeiraVezEm,
        ultimaVezEm: o.definicao.ultimaVezEm,
      })),
    });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

// ---------- Configurações / Chaves de API ----------

app.get('/api/configuracoes/chaves-api', autenticar, exigirPerfil('ADMINISTRADOR'), async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const chaves = await listarChavesApi(orgId);
    
    // Adicionar info dos provedores não configurados
    const provedoresConfigurados = new Set(chaves.map(c => c.provedor));
    const todosProvedores = Object.entries(PROVEDORES_INFO).map(([provedor, info]) => ({
      provedor,
      ...info,
      configurada: provedoresConfigurados.has(provedor as ProvedorApi),
      ...(chaves.find(c => c.provedor === provedor) || {}),
    }));
    
    res.json({ provedores: todosProvedores });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

app.post('/api/configuracoes/chaves-api', autenticar, exigirPerfil('ADMINISTRADOR'), async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const userId = req.usuario!.id;
    
    const schema = z.object({
      provedor: z.nativeEnum(ProvedorApi),
      chave: z.string().min(10),
    });
    
    const { provedor, chave } = schema.parse(req.body);
    
    await salvarChaveApi({
      organizacaoId: orgId,
      provedor,
      segredo: chave,
      usuarioId: userId,
    });
    
    res.json({ mensagem: 'Chave de API salva com sucesso' });
  } catch (erro: any) {
    res.status(400).json({ erro: erro.message });
  }
});

app.delete('/api/configuracoes/chaves-api/:provedor', autenticar, exigirPerfil('ADMINISTRADOR'), async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const provedor = req.params.provedor as ProvedorApi;
    
    await removerChaveApi(orgId, provedor);
    
    res.json({ mensagem: 'Chave de API removida com sucesso' });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

// ---------- Usuários ----------

app.get('/api/usuarios', autenticar, exigirPerfil('ADMINISTRADOR'), async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const membros = await prisma.membro.findMany({
      where: { organizacaoId: orgId },
      include: {
        usuario: {
          select: {
            id: true,
            nome: true,
            email: true,
            ativo: true,
            ultimoAcessoEm: true,
            criadoEm: true,
          },
        },
      },
    });
    
    res.json({
      usuarios: membros.map(m => ({
        id: m.usuario.id,
        nome: m.usuario.nome,
        email: m.usuario.email,
        perfil: m.perfil,
        ativo: m.usuario.ativo,
        ultimoAcessoEm: m.usuario.ultimoAcessoEm,
        criadoEm: m.usuario.criadoEm,
      })),
    });
  } catch (erro: any) {
    res.status(500).json({ erro: erro.message });
  }
});

app.post('/api/usuarios', autenticar, exigirPerfil('ADMINISTRADOR'), async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const schema = z.object({
      nome: z.string().min(2),
      email: z.string().email(),
      senha: z.string().min(8),
      perfil: z.nativeEnum(PerfilUsuario).default(PerfilUsuario.VISUALIZADOR),
    });
    
    const dados = schema.parse(req.body);
    
    // Verificar se e-mail já existe
    const existente = await prisma.usuario.findUnique({ where: { email: dados.email } });
    if (existente) {
      res.status(400).json({ erro: 'E-mail já cadastrado' });
      return;
    }
    
    const senhaHash = await hashSenha(dados.senha);
    
    const usuario = await prisma.usuario.create({
      data: {
        nome: dados.nome,
        email: dados.email,
        senhaHash,
        membros: {
          create: {
            organizacaoId: orgId,
            perfil: dados.perfil,
          },
        },
      },
    });
    
    res.status(201).json({
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        perfil: dados.perfil,
      },
    });
  } catch (erro: any) {
    res.status(400).json({ erro: erro.message });
  }
});

// ---------- Health Check ----------

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Tratamento de erros global
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Erro:', err);
  res.status(500).json({ erro: 'Erro interno do servidor' });
});

// Iniciar servidor
const PORT = env.PORT;
app.listen(PORT, () => {
  console.log(`🚀 Servidor Sentinela rodando na porta ${PORT}`);
});

export default app;
