// ============================================================================
// SENTINELA - Orquestrador de Varreduras
// Coordena a execução de todas as fontes de inteligência
// ============================================================================

import dns from 'dns/promises';
import { FonteInformacao, NivelRisco, Prisma, StatusVarredura, StatusExecucaoFonte } from '@prisma/client';
import { prisma } from '../config/prisma';
import { criarImpressaoDigital, sha256Hex } from '../utils/crypto';
import { obterChaveApi } from './chaveApiService';
import { obterCache, salvarCache } from './cacheService';
import { iniciarExecucaoFonte, finalizarExecucaoFonte, marcarChaveAusente } from './execucaoFonteService';

// Fontes de inteligência
import { descobrirSubdominios } from './sources/crtsh';
import { buscarAmeacasMarca } from './sources/urlscan';
import { buscarVazamentos } from './sources/leakix';
import { verificarReputacao } from './sources/virustotal';
import { buscarInfraestrutura } from './sources/shodan';
import { buscarIndicadoresAmeaca } from './sources/otx';
import { verificarReputacaoIP } from './sources/abuseipdb';
import { buscarEmPastes } from './sources/psbdmp';
import { verificarVazamentosDominio } from './sources/hibp';
import { buscarSecretsEmCodigo } from './sources/github';
import { buscarURLsMaliciosas } from './sources/urlhaus';
import { buscarIndicadoresMalware } from './sources/threatfox';
import { buscarVitimasRansomware } from './sources/ransomwarelive';
import { buscarCredenciaisComprometidas } from './sources/hudsonrock';
import { calcularScoreRisco, AchadoParaScore } from './riskScoreService';

import { AchadoCandidato, ResultadoFonte } from '../types';

// TTL de cache por fonte (em milissegundos)
const TTL_CACHE: Record<FonteInformacao, number> = {
  [FonteInformacao.CRTSH]: 24 * 60 * 60 * 1000,      // 24 horas
  [FonteInformacao.URLSCAN]: 60 * 60 * 1000,         // 1 hora
  [FonteInformacao.LEAKIX]: 60 * 60 * 1000,          // 1 hora
  [FonteInformacao.VIRUSTOTAL]: 6 * 60 * 60 * 1000,  // 6 horas
  [FonteInformacao.SHODAN]: 6 * 60 * 60 * 1000,      // 6 horas
  [FonteInformacao.OTX]: 6 * 60 * 60 * 1000,         // 6 horas
  [FonteInformacao.ABUSEIPDB]: 6 * 60 * 60 * 1000,   // 6 horas
  [FonteInformacao.PSBDMP]: 6 * 60 * 60 * 1000,      // 6 horas
  [FonteInformacao.HIBP]: 24 * 60 * 60 * 1000,       // 24 horas
  [FonteInformacao.GITHUB]: 12 * 60 * 60 * 1000,     // 12 horas
  [FonteInformacao.GOOGLE_DORKS]: 12 * 60 * 60 * 1000,
  [FonteInformacao.INTELX]: 12 * 60 * 60 * 1000,
};

function normalizarDominio(d: string): string {
  return d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
}

function normalizarEmail(e: string): string {
  return e.trim().toLowerCase();
}

// Executa função com cache
async function executarComCache<T>(
  fonte: FonteInformacao, 
  consultaRaw: string, 
  fn: () => Promise<T>
): Promise<{ dados: T; usouCache: boolean }> {
  const chave = sha256Hex(`${fonte}|${consultaRaw}`);
  const cached = await obterCache<T>(fonte, chave);
  
  if (cached) {
    return { dados: cached, usouCache: true };
  }
  
  const dados = await fn();
  await salvarCache(fonte, chave, dados as any, TTL_CACHE[fonte]);
  
  return { dados, usouCache: false };
}

// Persiste achados no banco de dados
async function persistirAchados(params: { 
  organizacaoId: string; 
  varreduraId: string; 
  achados: AchadoCandidato[] 
}) {
  const { organizacaoId, varreduraId, achados } = params;
  
  let criticos = 0, altos = 0, medios = 0, baixos = 0;
  
  for (const achado of achados) {
    // Criar impressão digital única para deduplicação
    const evidenciaSig = achado.evidencia ? sha256Hex(JSON.stringify(achado.evidencia)) : 'sem-evidencia';
    const impressaoDigital = criarImpressaoDigital({
      fonte: achado.fonte,
      tipo: achado.tipo,
      tipoEntidade: achado.tipoEntidade,
      entidade: achado.entidade,
      titulo: achado.titulo,
      evidenciaSig,
    });
    
    // Upsert da definição do achado
    const definicao = await prisma.definicaoAchado.upsert({
      where: { organizacaoId_impressaoDigital: { organizacaoId, impressaoDigital } },
      create: {
        organizacaoId,
        impressaoDigital,
        fonte: achado.fonte,
        nivelRisco: achado.nivelRisco,
        tipo: achado.tipo,
        tipoEntidade: achado.tipoEntidade,
        entidade: achado.entidade,
        titulo: achado.titulo,
        descricao: achado.descricao ?? null,
        recomendacao: achado.recomendacao ?? null,
        evidencia: (achado.evidencia ?? undefined) as Prisma.JsonValue | undefined,
        primeiraVezEm: new Date(),
        ultimaVezEm: new Date(),
      },
      update: {
        nivelRisco: achado.nivelRisco,
        titulo: achado.titulo,
        descricao: achado.descricao ?? null,
        recomendacao: achado.recomendacao ?? null,
        evidencia: (achado.evidencia ?? undefined) as Prisma.JsonValue | undefined,
        ultimaVezEm: new Date(),
      },
    });
    
    // Criar ocorrência vinculada à varredura
    await prisma.ocorrenciaAchado.upsert({
      where: { varreduraId_definicaoId: { varreduraId, definicaoId: definicao.id } },
      create: { varreduraId, definicaoId: definicao.id },
      update: {},
    });
    
    // Contar por nível de risco
    switch (achado.nivelRisco) {
      case NivelRisco.CRITICO: criticos++; break;
      case NivelRisco.ALTO: altos++; break;
      case NivelRisco.MEDIO: medios++; break;
      case NivelRisco.BAIXO: baixos++; break;
    }
  }
  
  return { criticos, altos, medios, baixos };
}

// Função principal de execução de varredura
export async function executarVarredura(varreduraId: string) {
  const varredura = await prisma.varredura.findUnique({
    where: { id: varreduraId },
    include: { empresa: { include: { dominios: true } } },
  });
  
  if (!varredura) throw new Error('Varredura não encontrada');
  
  const organizacaoId = varredura.empresa.organizacaoId;
  const dadosEntrada = varredura.dadosEntrada as any;
  const dominiosEntrada: string[] = Array.isArray(dadosEntrada.dominios) ? dadosEntrada.dominios : [];
  const emailsEntrada: string[] = Array.isArray(dadosEntrada.emails) ? dadosEntrada.emails : [];
  const varreduraProfunda = Boolean(dadosEntrada.varreduraProfunda);
  
  // Adicionar domínios cadastrados da empresa
  const dominiosCadastrados = varredura.empresa.dominios.map(d => d.dominio);
  const dominios = Array.from(new Set([...dominiosEntrada, ...dominiosCadastrados].map(normalizarDominio).filter(Boolean)));
  const emails = Array.from(new Set(emailsEntrada.map(normalizarEmail).filter(Boolean)));
  
  // Marcar como executando
  await prisma.varredura.update({
    where: { id: varreduraId },
    data: { status: StatusVarredura.EXECUTANDO, iniciadaEm: new Date() },
  });
  
  const todosAchados: AchadoCandidato[] = [];
  const alvos: string[] = [];
  const subdominiosPorRaiz: Record<string, string[]> = {};
  
  try {
    // =========================================================================
    // FASE 1: Discovery de Subdomínios (crt.sh)
    // =========================================================================
    if (dominios.length > 0 && varreduraProfunda) {
      for (const dominio of dominios) {
        const execucao = await iniciarExecucaoFonte({
          varreduraId,
          fonte: FonteInformacao.CRTSH,
          consulta: dominio,
        });
        
        const inicio = Date.now();
        try {
          const { dados, usouCache } = await executarComCache(
            FonteInformacao.CRTSH,
            dominio,
            () => descobrirSubdominios(dominio)
          );
          
          const subs = (dados as any).metadados?.subdominios as string[] | undefined;
          subdominiosPorRaiz[dominio] = Array.isArray(subs) ? subs : [];
          
          if (dados.achados?.length) {
            todosAchados.push(...dados.achados);
          }
          
          await finalizarExecucaoFonte(execucao.id, {
            status: usouCache ? StatusExecucaoFonte.CACHE : StatusExecucaoFonte.SUCESSO,
            duracaoMs: Date.now() - inicio,
            itensEncontrados: subdominiosPorRaiz[dominio]?.length ?? 0,
            usouCache,
            metadados: dados.metadados,
          });
        } catch (erro: any) {
          await finalizarExecucaoFonte(execucao.id, {
            status: StatusExecucaoFonte.ERRO,
            duracaoMs: Date.now() - inicio,
            mensagemErro: String(erro?.message ?? erro),
          });
        }
      }
    }
    
    // =========================================================================
    // FASE 2: Determinar alvos (domínios + subdomínios)
    // =========================================================================
    for (const dominio of dominios) {
      alvos.push(dominio);
      if (varreduraProfunda) {
        for (const sub of subdominiosPorRaiz[dominio] ?? []) {
          alvos.push(sub);
        }
      }
    }
    const alvosUnicos = Array.from(new Set(alvos));
    
    // =========================================================================
    // FASE 3: Executar fontes baseadas em domínio
    // =========================================================================
    
    // Helper para executar fonte com rastreamento
    const executarFonteDominio = async (
      fonte: FonteInformacao,
      consulta: string,
      executar: (chaveApi?: string | null) => Promise<ResultadoFonte>,
      provedor?: any
    ) => {
      const execucao = await iniciarExecucaoFonte({ varreduraId, fonte, consulta });
      const inicio = Date.now();
      
      try {
        let chaveApi: string | null = null;
        
        if (provedor) {
          chaveApi = await obterChaveApi(organizacaoId, provedor);
          if (!chaveApi) {
            await marcarChaveAusente(execucao.id);
            return;
          }
        }
        
        const { dados, usouCache } = await executarComCache(fonte, consulta, () => executar(chaveApi));
        
        if (dados.achados?.length) {
          todosAchados.push(...dados.achados);
        }
        
        await finalizarExecucaoFonte(execucao.id, {
          status: usouCache ? StatusExecucaoFonte.CACHE : StatusExecucaoFonte.SUCESSO,
          duracaoMs: Date.now() - inicio,
          itensEncontrados: dados.itensEncontrados ?? dados.achados?.length ?? 0,
          usouCache,
          metadados: dados.metadados,
        });
      } catch (erro: any) {
        const mensagemErro = String(erro?.message ?? erro);
        let status = StatusExecucaoFonte.ERRO;
        
        // Manter como ERRO - os valores TIMEOUT e LIMITE_TAXA não existem no enum
        // O erro já está registrado na mensagem de erro
        if (mensagemErro.includes('timeout') || mensagemErro.includes('TIMEOUT')) {
          // Timeout detectado - registrar na mensagem
        } else if (mensagemErro.includes('rate') || mensagemErro.includes('429')) {
          // Rate limit detectado - registrar na mensagem
        }
        
        await finalizarExecucaoFonte(execucao.id, {
          status,
          duracaoMs: Date.now() - inicio,
          mensagemErro,
        });
      }
    };
    
    // Executar para cada alvo (limitando para não demorar muito)
    const alvosLimitados = alvosUnicos.slice(0, 10);
    
    for (const alvo of alvosLimitados) {
      // URLScan - Detecção de phishing/impersonação
      await executarFonteDominio(FonteInformacao.URLSCAN, alvo, (k) => buscarAmeacasMarca(alvo, k), 'URLSCAN');
      
      // LeakIX - Vazamentos e configurações expostas
      await executarFonteDominio(FonteInformacao.LEAKIX, alvo, (k) => buscarVazamentos(alvo, k!), 'LEAKIX');
      
      // VirusTotal - Reputação do domínio
      await executarFonteDominio(FonteInformacao.VIRUSTOTAL, alvo, (k) => verificarReputacao(alvo, k!), 'VT');
      
      // Shodan - Infraestrutura exposta
      await executarFonteDominio(FonteInformacao.SHODAN, alvo, (k) => buscarInfraestrutura(alvo, k!), 'SHODAN');
      
      // OTX - Indicadores de ameaças
      await executarFonteDominio(FonteInformacao.OTX, alvo, (k) => buscarIndicadoresAmeaca(alvo, k), 'OTX');
      
      // PSBDMP - Busca em pastes (não requer API key)
      await executarFonteDominio(FonteInformacao.PSBDMP, alvo, () => buscarEmPastes(alvo));
      
      // AbuseIPDB - Verificar IPs do domínio
      const chaveAbuse = await obterChaveApi(organizacaoId, 'ABUSEIPDB');
      if (chaveAbuse) {
        try {
          const ips = await dns.resolve4(alvo);
          for (const ip of Array.from(new Set(ips)).slice(0, 3)) {
            await executarFonteDominio(FonteInformacao.ABUSEIPDB, ip, () => verificarReputacaoIP(ip, chaveAbuse));
          }
        } catch {
          // Domínio não resolve para IP, ignorar
        }
      }
    }
    
    // =========================================================================
    // FASE 4: GitHub Code Search (buscar secrets)
    // =========================================================================
    for (const dominio of dominios.slice(0, 3)) {
      await executarFonteDominio(FonteInformacao.GITHUB, dominio, (k) => buscarSecretsEmCodigo(dominio, k), 'GITHUB');
    }
    
    // =========================================================================
    // FASE 5: Novas Fontes de Threat Intelligence (APIs Gratuitas)
    // =========================================================================
    
    // URLhaus - URLs de malware (Abuse.ch - grátis)
    for (const dominio of dominios.slice(0, 3)) {
      const execucao = await iniciarExecucaoFonte({
        varreduraId,
        fonte: FonteInformacao.OTX, // Usando OTX como proxy
        consulta: `urlhaus:${dominio}`,
      });
      
      const inicio = Date.now();
      try {
        const resultado = await buscarURLsMaliciosas(dominio);
        
        if (resultado.achados?.length) {
          todosAchados.push(...resultado.achados);
        }
        
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.SUCESSO,
          duracaoMs: Date.now() - inicio,
          itensEncontrados: resultado.itensEncontrados,
          metadados: { ...resultado.metadados, fonte: 'URLhaus' },
        });
      } catch (erro: any) {
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.ERRO,
          duracaoMs: Date.now() - inicio,
          mensagemErro: String(erro?.message ?? erro),
        });
      }
    }
    
    // ThreatFox - IoCs de malware (Abuse.ch - grátis)
    for (const dominio of dominios.slice(0, 3)) {
      const execucao = await iniciarExecucaoFonte({
        varreduraId,
        fonte: FonteInformacao.OTX, // Usando OTX como proxy
        consulta: `threatfox:${dominio}`,
      });
      
      const inicio = Date.now();
      try {
        const resultado = await buscarIndicadoresMalware(dominio);
        
        if (resultado.achados?.length) {
          todosAchados.push(...resultado.achados);
        }
        
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.SUCESSO,
          duracaoMs: Date.now() - inicio,
          itensEncontrados: resultado.itensEncontrados,
          metadados: { ...resultado.metadados, fonte: 'ThreatFox' },
        });
      } catch (erro: any) {
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.ERRO,
          duracaoMs: Date.now() - inicio,
          mensagemErro: String(erro?.message ?? erro),
        });
      }
    }
    
    // Ransomware.live - Vítimas de ransomware (grátis)
    for (const dominio of dominios.slice(0, 2)) {
      const execucao = await iniciarExecucaoFonte({
        varreduraId,
        fonte: FonteInformacao.LEAKIX, // Usando LEAKIX como proxy
        consulta: `ransomware:${dominio}`,
      });
      
      const inicio = Date.now();
      try {
        const nomeEmpresa = varredura.empresa.nome;
        const resultado = await buscarVitimasRansomware(dominio, nomeEmpresa);
        
        if (resultado.achados?.length) {
          todosAchados.push(...resultado.achados);
        }
        
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.SUCESSO,
          duracaoMs: Date.now() - inicio,
          itensEncontrados: resultado.itensEncontrados,
          metadados: { ...resultado.metadados, fonte: 'Ransomware.live' },
        });
      } catch (erro: any) {
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.ERRO,
          duracaoMs: Date.now() - inicio,
          mensagemErro: String(erro?.message ?? erro),
        });
      }
    }
    
    // Hudson Rock - Credenciais comprometidas por infostealers (grátis)
    for (const dominio of dominios.slice(0, 2)) {
      const execucao = await iniciarExecucaoFonte({
        varreduraId,
        fonte: FonteInformacao.LEAKIX, // Usando LEAKIX como proxy
        consulta: `hudsonrock:${dominio}`,
      });
      
      const inicio = Date.now();
      try {
        const resultado = await buscarCredenciaisComprometidas(dominio);
        
        if (resultado.achados?.length) {
          todosAchados.push(...resultado.achados);
        }
        
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.SUCESSO,
          duracaoMs: Date.now() - inicio,
          itensEncontrados: resultado.itensEncontrados,
          metadados: { ...resultado.metadados, fonte: 'Hudson Rock' },
        });
      } catch (erro: any) {
        await finalizarExecucaoFonte(execucao.id, {
          status: StatusExecucaoFonte.ERRO,
          duracaoMs: Date.now() - inicio,
          mensagemErro: String(erro?.message ?? erro),
        });
      }
    }
    
    // =========================================================================
    // FASE 6: HIBP - Verificar vazamentos de e-mail
    // =========================================================================
    const chaveHibp = await obterChaveApi(organizacaoId, 'HIBP');
    if (chaveHibp && dominios.length > 0) {
      for (const dominio of dominios.slice(0, 2)) {
        const execucao = await iniciarExecucaoFonte({
          varreduraId,
          fonte: FonteInformacao.HIBP,
          consulta: dominio,
        });
        
        const inicio = Date.now();
        try {
          const resultado = await verificarVazamentosDominio(dominio, chaveHibp, emails);
          
          if (resultado.achados?.length) {
            todosAchados.push(...resultado.achados);
          }
          
          await finalizarExecucaoFonte(execucao.id, {
            status: StatusExecucaoFonte.SUCESSO,
            duracaoMs: Date.now() - inicio,
            itensEncontrados: resultado.itensEncontrados,
            metadados: resultado.metadados,
          });
        } catch (erro: any) {
          await finalizarExecucaoFonte(execucao.id, {
            status: StatusExecucaoFonte.ERRO,
            duracaoMs: Date.now() - inicio,
            mensagemErro: String(erro?.message ?? erro),
          });
        }
      }
    } else if (dominios.length > 0) {
      const execucao = await iniciarExecucaoFonte({
        varreduraId,
        fonte: FonteInformacao.HIBP,
        consulta: 'verificacao-emails',
      });
      await marcarChaveAusente(execucao.id);
    }
    
    // =========================================================================
    // FASE 6: Persistir achados e finalizar
    // =========================================================================
    const contagem = await persistirAchados({
      organizacaoId,
      varreduraId,
      achados: todosAchados,
    });
    
    await prisma.varredura.update({
      where: { id: varreduraId },
      data: {
        status: StatusVarredura.CONCLUIDA,
        concluidaEm: new Date(),
        totalAchados: todosAchados.length,
        achadosCriticos: contagem.criticos,
        achadosAltos: contagem.altos,
        achadosMedios: contagem.medios,
        achadosBaixos: contagem.baixos,
      },
    });
    
    // Calcular score de risco
    const achadosParaScore: AchadoParaScore[] = todosAchados.map(a => ({
      nivelRisco: a.nivelRisco,
      fonte: a.fonte,
      tipo: a.tipo,
    }));
    const scoreRisco = calcularScoreRisco(achadosParaScore);
    
    // Score de risco calculado - será usado no PDF e na interface
    // O score é retornado junto com os achados na API
    console.log(`Score de risco calculado: ${scoreRisco.pontuacao} (${scoreRisco.classificacao})`);
    
    // Gerar relatório PDF
    // await gerarRelatorio(varreduraId);
    
  } catch (erro: any) {
    await prisma.varredura.update({
      where: { id: varreduraId },
      data: {
        status: StatusVarredura.FALHOU,
        concluidaEm: new Date(),
        mensagemErro: String(erro?.message ?? erro),
      },
    });
    throw erro;
  }
}
