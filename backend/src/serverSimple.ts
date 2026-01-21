// ============================================================================
// SENTINELA - Servidor Express Simplificado com Supabase REST API
// ============================================================================

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import { calculateFinalScore, getRiskLevel, DEFAULT_WEIGHTS, type ScoringAxes, calculateAllAxes, scoreFinding } from './services/advancedScoringService';
import { classifyFinding, getVulnClassDetails, type VulnClass } from './services/vulnClassService';
import { getLGPDCrosswalk } from './services/lgpdCrosswalkService';

// Configuração
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'sentinela-ti-jwt-secret-key-2024-very-secure-random-string';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// Cliente Supabase
const supabaseUrl = process.env.SUPABASE_URL || 'https://exdmibuizlvhyczpqvio.supabase.co';
const supabaseKey = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4ZG1pYnVpemx2aHljenBxdmlvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njg2MDA3MTcsImV4cCI6MjA4NDE3NjcxN30.wl4ZB6i6sm2CoyEFNAX6stfY3I1gHD5WNIGF_XhS_VQ';
const supabase = createClient(supabaseUrl, supabaseKey);

const app = express();

// Middlewares globais
app.use(helmet());
app.use(cors({ origin: '*', credentials: true }));
app.use(compression());
app.use(express.json({ limit: '10mb' }));

// Interface para usuário autenticado
interface UsuarioAutenticado {
  id: string;
  email: string;
  nome?: string;
  organizacaoId: string;
  perfil: string;
}

declare global {
  namespace Express {
    interface Request {
      usuario?: UsuarioAutenticado;
    }
  }
}

// Middleware de autenticação
const autenticar = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ erro: 'Token não fornecido' });
      return;
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    req.usuario = {
      id: decoded.sub,
      email: decoded.email,
      organizacaoId: decoded.organizacaoId,
      perfil: decoded.perfil,
    };
    
    next();
  } catch (erro) {
    res.status(401).json({ erro: 'Token inválido' });
  }
};

// ============================================================================
// ROTAS PÚBLICAS
// ============================================================================

// Health check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Login
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const schema = z.object({
      email: z.string().email(),
      senha: z.string().min(6),
    });
    
    const { email, senha } = schema.parse(req.body);
    
    // Buscar usuário
    const { data: usuario, error: userError } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email)
      .single();
    
    if (userError || !usuario) {
      res.status(401).json({ erro: 'Credenciais inválidas' });
      return;
    }
    
    if (!usuario.ativo) {
      res.status(401).json({ erro: 'Usuário inativo' });
      return;
    }
    
    // Verificar senha
    const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaValida) {
      res.status(401).json({ erro: 'Credenciais inválidas' });
      return;
    }
    
    // Buscar membro e organização
    const { data: membro, error: membroError } = await supabase
      .from('membros')
      .select('*, organizacoes(*)')
      .eq('usuario_id', usuario.id)
      .single();
    
    if (membroError || !membro) {
      res.status(401).json({ erro: 'Usuário não pertence a nenhuma organização' });
      return;
    }
    
    // Atualizar último acesso
    await supabase
      .from('usuarios')
      .update({ ultimo_acesso_em: new Date().toISOString() })
      .eq('id', usuario.id);
    
    // Gerar tokens
    const tokenAcesso = jwt.sign(
      {
        sub: usuario.id,
        email: usuario.email,
        organizacaoId: membro.organizacao_id,
        perfil: membro.perfil,
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    const tokenRefresh = jwt.sign(
      { sub: usuario.id, type: 'refresh' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      tokenAcesso,
      tokenRefresh,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        perfil: membro.perfil,
        organizacao: {
          id: membro.organizacoes.id,
          nome: membro.organizacoes.nome,
        },
      },
    });
  } catch (erro: any) {
    console.error('Erro no login:', erro);
    res.status(400).json({ erro: erro.message });
  }
});

// Refresh token
app.post('/api/auth/refresh', async (req: Request, res: Response) => {
  try {
    const { tokenRefresh } = req.body;
    
    if (!tokenRefresh) {
      res.status(400).json({ erro: 'Token de refresh não fornecido' });
      return;
    }
    
    const decoded = jwt.verify(tokenRefresh, JWT_SECRET) as any;
    
    if (decoded.type !== 'refresh') {
      res.status(401).json({ erro: 'Token inválido' });
      return;
    }
    
    // Buscar usuário
    const { data: usuario, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('id', decoded.sub)
      .single();
    
    if (error || !usuario || !usuario.ativo) {
      res.status(401).json({ erro: 'Usuário não encontrado ou inativo' });
      return;
    }
    
    // Buscar membro
    const { data: membro } = await supabase
      .from('membros')
      .select('*, organizacoes(*)')
      .eq('usuario_id', usuario.id)
      .single();
    
    if (!membro) {
      res.status(401).json({ erro: 'Usuário não pertence a nenhuma organização' });
      return;
    }
    
    // Gerar novo token de acesso
    const novoTokenAcesso = jwt.sign(
      {
        sub: usuario.id,
        email: usuario.email,
        organizacaoId: membro.organizacao_id,
        perfil: membro.perfil,
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    res.json({ tokenAcesso: novoTokenAcesso });
  } catch (erro: any) {
    res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
});

// ============================================================================
// ROTAS PROTEGIDAS
// ============================================================================

// Dashboard
app.get('/api/dashboard', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    // Estatísticas
    const { count: totalEmpresas } = await supabase
      .from('empresas')
      .select('id', { count: 'exact', head: true })
      .eq('organizacao_id', orgId)
      .eq('ativa', true);
    
    const { count: empresasMonitoradas } = await supabase
      .from('monitoramento_empresas')
      .select('id', { count: 'exact', head: true })
      .eq('ativo', true);
    
    const { count: totalAchados } = await supabase
      .from('definicoes_achado')
      .select('id', { count: 'exact', head: true })
      .eq('organizacao_id', orgId);
    
    const { count: achadosCriticos } = await supabase
      .from('definicoes_achado')
      .select('id', { count: 'exact', head: true })
      .eq('organizacao_id', orgId)
      .eq('nivel_risco', 'CRITICO')
      .eq('status', 'ABERTO');
    
    const { count: achadosAltos } = await supabase
      .from('definicoes_achado')
      .select('id', { count: 'exact', head: true })
      .eq('organizacao_id', orgId)
      .eq('nivel_risco', 'ALTO')
      .eq('status', 'ABERTO');
    
    // Últimas varreduras
    const { data: ultimasVarreduras } = await supabase
      .from('varreduras')
      .select('*, empresas(nome)')
      .order('criado_em', { ascending: false })
      .limit(5);
    
    // Últimos achados
    const { data: ultimosAchados } = await supabase
      .from('definicoes_achado')
      .select('*')
      .eq('organizacao_id', orgId)
      .order('ultima_vez_em', { ascending: false })
      .limit(10);
    
    res.json({
      estatisticas: {
        totalEmpresas: totalEmpresas || 0,
        empresasMonitoradas: empresasMonitoradas || 0,
        varredurasUltimos30Dias: 0,
        totalAchados: totalAchados || 0,
        achadosCriticos: achadosCriticos || 0,
        achadosAltos: achadosAltos || 0,
      },
      ultimasVarreduras: (ultimasVarreduras || []).map((v: any) => ({
        id: v.id,
        empresa: v.empresas?.nome || 'N/A',
        status: v.status,
        totalAchados: v.total_achados,
        achadosCriticos: v.achados_criticos,
        criadoEm: v.criado_em,
      })),
      ultimosAchados: (ultimosAchados || []).map((a: any) => ({
        id: a.id,
        titulo: a.titulo,
        nivelRisco: a.nivel_risco,
        fonte: a.fonte,
        empresa: 'N/A',
        ultimaVezEm: a.ultima_vez_em,
      })),
      distribuicaoPorRisco: {},
      distribuicaoPorFonte: {},
    });
  } catch (erro: any) {
    console.error('Erro no dashboard:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Empresas
app.get('/api/empresas', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const { data: empresas, error } = await supabase
      .from('empresas')
      .select('*, dominios_empresa(*), monitoramento_empresas(*)')
      .eq('organizacao_id', orgId)
      .order('nome');
    
    if (error) throw error;
    
    res.json({
      empresas: (empresas || []).map((e: any) => ({
        id: e.id,
        nome: e.nome,
        nomeFantasia: e.nome_fantasia,
        cnpj: e.cnpj,
        setor: e.setor,
        dominios: (e.dominios_empresa || []).map((d: any) => d.dominio),
        ativa: e.ativa,
        monitorada: e.monitoramento_empresas?.[0]?.ativo ?? false,
        totalVarreduras: 0,
        criadoEm: e.criado_em,
      })),
      total: empresas?.length || 0,
      paginas: 1,
    });
  } catch (erro: any) {
    console.error('Erro ao listar empresas:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Criar empresa
app.post('/api/empresas', autenticar, async (req: Request, res: Response) => {
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
    
    // Criar empresa
    const { data: empresa, error: empresaError } = await supabase
      .from('empresas')
      .insert({
        organizacao_id: orgId,
        nome: dados.nome,
        nome_fantasia: dados.nomeFantasia,
        cnpj: dados.cnpj,
        setor: dados.setor,
        email_principal: dados.emailPrincipal,
        criado_por_id: userId,
      })
      .select()
      .single();
    
    if (empresaError) throw empresaError;
    
    // Criar domínios
    for (let i = 0; i < dados.dominios.length; i++) {
      await supabase.from('dominios_empresa').insert({
        empresa_id: empresa.id,
        dominio: dados.dominios[i].toLowerCase().trim(),
        principal: i === 0,
      });
    }
    
    res.status(201).json({ empresa });
  } catch (erro: any) {
    console.error('Erro ao criar empresa:', erro);
    res.status(400).json({ erro: erro.message });
  }
});

// Detalhes da empresa
app.get('/api/empresas/:id', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const { data: empresa, error } = await supabase
      .from('empresas')
      .select('*, dominios_empresa(*), monitoramento_empresas(*)')
      .eq('id', req.params.id)
      .eq('organizacao_id', orgId)
      .single();
    
    if (error || !empresa) {
      res.status(404).json({ erro: 'Empresa não encontrada' });
      return;
    }
    
    res.json({
      empresa: {
        id: empresa.id,
        nome: empresa.nome,
        nomeFantasia: empresa.nome_fantasia,
        cnpj: empresa.cnpj,
        setor: empresa.setor,
        emailPrincipal: empresa.email_principal,
        dominios: (empresa.dominios_empresa || []).map((d: any) => ({
          id: d.id,
          dominio: d.dominio,
          principal: d.principal,
        })),
        ativa: empresa.ativa,
        monitoramento: empresa.monitoramento_empresas?.[0] || null,
        criadoEm: empresa.criado_em,
      },
    });
  } catch (erro: any) {
    console.error('Erro ao buscar empresa:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Chaves de API - Listar
app.get('/api/chaves-api', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const { data: chaves, error } = await supabase
      .from('chaves_api')
      .select('*')
      .eq('organizacao_id', orgId);
    
    if (error) throw error;
    
    // Lista de provedores disponíveis
    const provedores = [
      { id: 'HIBP', nome: 'Have I Been Pwned', descricao: 'Verificação de vazamentos de dados' },
      { id: 'VT', nome: 'VirusTotal', descricao: 'Análise de malware e URLs' },
      { id: 'SHODAN', nome: 'Shodan', descricao: 'Busca de dispositivos expostos' },
      { id: 'LEAKIX', nome: 'LeakIX', descricao: 'Detecção de vazamentos' },
      { id: 'OTX', nome: 'AlienVault OTX', descricao: 'Inteligência de ameaças' },
      { id: 'ABUSEIPDB', nome: 'AbuseIPDB', descricao: 'Reputação de IPs' },
      { id: 'URLSCAN', nome: 'URLScan', descricao: 'Análise de URLs' },
      { id: 'PSBDMP', nome: 'Pastebin Dumps', descricao: 'Monitoramento de pastes' },
      { id: 'GITHUB', nome: 'GitHub', descricao: 'Busca de código vazado' },
      { id: 'INTELX', nome: 'Intelligence X', descricao: 'Inteligência de ameaças avançada' },
      { id: 'HUDSON_ROCK', nome: 'Hudson Rock (Cavalier)', descricao: 'Detecção de infostealers' },
    ];
    
    const chavesMap = new Map((chaves || []).map((c: any) => [c.provedor, c]));
    
    res.json({
      provedores: provedores.map(p => ({
        ...p,
        configurada: chavesMap.has(p.id),
        ativa: chavesMap.get(p.id)?.ativa ?? false,
        ultimoUso: chavesMap.get(p.id)?.ultimo_uso_em,
      })),
    });
  } catch (erro: any) {
    console.error('Erro ao listar chaves:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Chaves de API - Salvar
app.post('/api/chaves-api/:provedor', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const userId = req.usuario!.id;
    const { provedor } = req.params;
    const { chave } = req.body;
    
    if (!chave) {
      res.status(400).json({ erro: 'Chave não fornecida' });
      return;
    }
    
    // Verificar se já existe
    const { data: existente } = await supabase
      .from('chaves_api')
      .select('id')
      .eq('organizacao_id', orgId)
      .eq('provedor', provedor)
      .single();
    
    if (existente) {
      // Atualizar
      await supabase
        .from('chaves_api')
        .update({
          segredo_criptografado: chave, // Em produção, criptografar
          ativa: true,
          atualizado_em: new Date().toISOString(),
        })
        .eq('id', existente.id);
    } else {
      // Criar
      await supabase
        .from('chaves_api')
        .insert({
          organizacao_id: orgId,
          provedor: provedor,
          segredo_criptografado: chave, // Em produção, criptografar
          ativa: true,
          criado_por_id: userId,
        });
    }
    
    res.json({ sucesso: true });
  } catch (erro: any) {
    console.error('Erro ao salvar chave:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Chaves de API - Remover
app.delete('/api/chaves-api/:provedor', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const { provedor } = req.params;
    
    await supabase
      .from('chaves_api')
      .delete()
      .eq('organizacao_id', orgId)
      .eq('provedor', provedor);
    
    res.json({ sucesso: true });
  } catch (erro: any) {
    console.error('Erro ao remover chave:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Usuário atual
app.get('/api/usuarios/me', autenticar, async (req: Request, res: Response) => {
  try {
    const { data: usuario, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('id', req.usuario!.id)
      .single();
    
    if (error || !usuario) {
      res.status(404).json({ erro: 'Usuário não encontrado' });
      return;
    }
    
    const { data: membro } = await supabase
      .from('membros')
      .select('*, organizacoes(*)')
      .eq('usuario_id', usuario.id)
      .single();
    
    res.json({
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        avatarUrl: usuario.avatar_url,
        perfil: membro?.perfil || 'VISUALIZADOR',
        organizacao: membro?.organizacoes ? {
          id: membro.organizacoes.id,
          nome: membro.organizacoes.nome,
        } : null,
      },
    });
  } catch (erro: any) {
    console.error('Erro ao buscar usuário:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// ============================================================================
// ROTAS DE VARREDURA COM SCORING, VULNCLASS E LGPD CROSSWALK
// ============================================================================



// Listar varreduras
app.get('/api/varreduras', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    
    const { data: varreduras, error } = await supabase
      .from('varreduras')
      .select('*, empresas(nome)')
      .order('criado_em', { ascending: false })
      .limit(50);
    
    if (error) throw error;
    
    res.json({
      varreduras: (varreduras || []).map((v: any) => ({
        id: v.id,
        empresaId: v.empresa_id,
        empresa: v.empresas?.nome || 'N/A',
        status: v.status,
        totalAchados: v.total_achados || 0,
        achadosCriticos: v.achados_criticos || 0,
        achadosAltos: v.achados_altos || 0,
        criadoEm: v.criado_em,
        finalizadoEm: v.finalizado_em,
      })),
      total: varreduras?.length || 0,
    });
  } catch (erro: any) {
    console.error('Erro ao listar varreduras:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Detalhes de uma varredura
app.get('/api/varreduras/:id', autenticar, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    const { data: varredura, error } = await supabase
      .from('varreduras')
      .select('*, empresas(nome, dominios_empresa(dominio))')
      .eq('id', id)
      .single();
    
    if (error || !varredura) {
      res.status(404).json({ erro: 'Varredura não encontrada' });
      return;
    }
    
    // Buscar achados da varredura
    const { data: achados } = await supabase
      .from('definicoes_achado')
      .select('*')
      .eq('varredura_id', id)
      .order('nivel_risco', { ascending: false });
    
    res.json({
      varredura: {
        id: varredura.id,
        empresaId: varredura.empresa_id,
        empresa: varredura.empresas?.nome || 'N/A',
        dominios: varredura.empresas?.dominios_empresa?.map((d: any) => d.dominio) || [],
        status: varredura.status,
        totalAchados: varredura.total_achados || 0,
        achadosCriticos: varredura.achados_criticos || 0,
        achadosAltos: varredura.achados_altos || 0,
        criadoEm: varredura.criado_em,
        finalizadoEm: varredura.finalizado_em,
      },
      achados: (achados || []).map((a: any) => ({
        id: a.id,
        titulo: a.titulo,
        descricao: a.descricao,
        fonte: a.fonte,
        nivelRisco: a.nivel_risco,
        status: a.status,
        vulnClass: a.vuln_class,
        scoreAxes: a.score_axes,
        scoreFinal: a.score_final,
        lgpdArticles: a.lgpd_articles,
        anpdNotificationRequired: a.anpd_notification_required,
        primeiraVezEm: a.primeira_vez_em,
        ultimaVezEm: a.ultima_vez_em,
      })),
    });
  } catch (erro: any) {
    console.error('Erro ao buscar varredura:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Criar nova varredura
app.post('/api/varreduras', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const userId = req.usuario!.id;
    const { empresaId, dominios } = req.body;
    
    if (!empresaId) {
      res.status(400).json({ erro: 'empresaId é obrigatório' });
      return;
    }
    
    // Criar varredura
    const { data: varredura, error } = await supabase
      .from('varreduras')
      .insert({
        empresa_id: empresaId,
        status: 'PENDENTE',
        criado_por_id: userId,
      })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json({ varredura });
  } catch (erro: any) {
    console.error('Erro ao criar varredura:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Endpoint para calcular score de um achado
app.post('/api/scoring/calcular', autenticar, async (req: Request, res: Response) => {
  try {
    const { fonte, tipo, dados, source, type, count, dataTypes, isPubliclyExposed } = req.body;
    
    // Suportar ambos os formatos de entrada
    const actualFonte = fonte || source || '';
    const actualTipo = tipo || type || '';
    const actualDados = dados || { count, dataTypes, isPubliclyExposed, titulo: actualTipo, descricao: '' };
    
    // Classificar o achado
    const vulnClass = classifyFinding({
      fonte: actualFonte,
      titulo: actualDados.titulo || actualTipo || '',
      descricao: actualDados.descricao || '',
      nivelRisco: actualDados.nivelRisco || 'MEDIO',
      tipo: actualTipo,
    });
    const vulnClassDetails = getVulnClassDetails(vulnClass);
    
    // Calcular eixos de scoring baseado nos dados
    const axes: ScoringAxes = {
      exposure: vulnClassDetails.defaultExposure,
      exploitability: vulnClassDetails.defaultExploitability,
      dataSensitivity: vulnClassDetails.defaultDataSensitivity,
      scale: Math.min(1, (actualDados.count || 1) / 100), // Normalizar para 0-1
      confidence: 0.85 // Confiança padrão
    };
    
    // Calcular score final
    const scoreFinalValue = calculateFinalScore(axes, DEFAULT_WEIGHTS);
    const riskLevel = getRiskLevel(scoreFinalValue);
    
    // Obter mapeamento LGPD
    const lgpdCrosswalk = getLGPDCrosswalk(vulnClass);
    const anpdRequired = lgpdCrosswalk.requiresANPDNotification;
    
    res.json({
      vulnClass,
      vulnClassDetails,
      scoreAxes: {
        exposure: Math.round(axes.exposure * 100),
        exploitability: Math.round(axes.exploitability * 100),
        dataSensitivity: Math.round(axes.dataSensitivity * 100),
        scale: Math.round(axes.scale * 100),
        confidence: Math.round(axes.confidence * 100),
      },
      scoreFinal: Math.round(scoreFinalValue),
      riskLevel,
      lgpd: {
        articles: lgpdCrosswalk.applicableArticles.map(a => a.number),
        anpdCriteria: lgpdCrosswalk.anpdCriteria.map(c => c.name),
        notificationRequired: anpdRequired,
        deadlineDays: anpdRequired ? 3 : null,
        recommendations: lgpdCrosswalk.recommendations,
      },
    });
  } catch (erro: any) {
    console.error('Erro ao calcular score:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Endpoint para obter detalhes de VulnClass
app.get('/api/vulnclass/:class', autenticar, async (req: Request, res: Response) => {
  try {
    const vulnClass = req.params.class as VulnClass;
    const details = getVulnClassDetails(vulnClass);
    const lgpdCrosswalk = getLGPDCrosswalk(vulnClass);
    
    res.json({
      ...details,
      lgpd: lgpdCrosswalk,
    });
  } catch (erro: any) {
    console.error('Erro ao buscar VulnClass:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Endpoint para listar todas as VulnClasses
app.get('/api/vulnclasses', autenticar, async (req: Request, res: Response) => {
  try {
    const classes: VulnClass[] = [
      'SECRETS_LEAK',
      'DATA_EXPOSURE_PUBLIC',
      'PHISHING_SOCIAL_ENG',
      'RANSOMWARE_IMPACT',
      'UNPATCHED_EXPLOITED',
      'MALWARE_C2',
      'ACCOUNT_TAKEOVER',
      'THIRD_PARTY_RISK'
    ];
    
    const result = classes.map(vc => {
      const details = getVulnClassDetails(vc);
      const lgpd = getLGPDCrosswalk(vc);
      return {
        ...details,
        lgpd: {
          articles: lgpd.applicableArticles.map(a => a.number),
          notificationRequired: lgpd.requiresANPDNotification,
        },
      };
    });
    
    res.json({ vulnClasses: result });
  } catch (erro: any) {
    console.error('Erro ao listar VulnClasses:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Endpoint para obter mapeamento LGPD completo
app.get('/api/lgpd/crosswalk/:vulnClass', autenticar, async (req: Request, res: Response) => {
  try {
    const vulnClass = req.params.vulnClass as VulnClass;
    const crosswalk = getLGPDCrosswalk(vulnClass);
    
    res.json(crosswalk);
  } catch (erro: any) {
    console.error('Erro ao buscar crosswalk LGPD:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Endpoint para verificar necessidade de notificação ANPD
app.post('/api/lgpd/check-notification', autenticar, async (req: Request, res: Response) => {
  try {
    const { vulnClass, scoreFinal, recordCount } = req.body;
    
    const crosswalk = getLGPDCrosswalk(vulnClass as VulnClass);
    const required = crosswalk.requiresANPDNotification;
    
    res.json({
      notificationRequired: required,
      deadlineDays: required ? 3 : null,
      articles: crosswalk.applicableArticles.map(a => a.number),
      anpdCriteria: crosswalk.anpdCriteria.filter(c => c.requiresNotification).map(c => c.name),
      recommendations: crosswalk.recommendations,
    });
  } catch (erro: any) {
    console.error('Erro ao verificar notificação ANPD:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor Sentinela rodando na porta ${PORT}`);
  console.log(`Supabase URL: ${supabaseUrl}`);
  console.log('Sistema de Scoring 5 Eixos: ATIVO');
  console.log('Sistema de VulnClasses: ATIVO');
  console.log('Sistema de LGPD Crosswalk: ATIVO');
});
