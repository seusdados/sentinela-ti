// ============================================================================
// SENTINELA - Integração com Hudson Rock (Cavalier)
// Detecta credenciais comprometidas por infostealers
// API: https://cavalier.hudsonrock.com/api/json/v2/
// ============================================================================

import axios from 'axios';
import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { AchadoCandidato, ResultadoFonte } from '../../types';

const HUDSON_ROCK_API = 'https://cavalier.hudsonrock.com/api/json/v2';

interface HudsonRockCredential {
  email: string;
  url: string;
  username: string;
  password: string;
  date_compromised: string;
  malware_family: string;
  computer_name: string;
  operating_system: string;
  ip: string;
  antiviruses: string[];
}

interface HudsonRockResponse {
  message?: string;
  stealers?: HudsonRockCredential[];
  total_results?: number;
}

/**
 * Mascara uma senha para exibição segura
 * Mostra apenas os 3 primeiros e 3 últimos caracteres
 */
function maskPassword(password: string): string {
  if (!password || password.length < 8) {
    return '***masked***';
  }
  const start = password.substring(0, 3);
  const end = password.substring(password.length - 3);
  const middleLength = Math.min(password.length - 6, 10);
  return `${start}${'*'.repeat(middleLength)}${end}`;
}

/**
 * Analisa a força de uma senha
 */
function analyzePasswordStrength(password: string): {
  strength: 'MUITO_FRACA' | 'FRACA' | 'MEDIA' | 'FORTE';
  issues: string[];
} {
  const issues: string[] = [];
  let score = 0;
  
  if (!password) {
    return { strength: 'MUITO_FRACA', issues: ['Senha vazia'] };
  }
  
  // Comprimento
  if (password.length >= 12) score += 2;
  else if (password.length >= 8) score += 1;
  else issues.push('Menos de 8 caracteres');
  
  // Letras maiúsculas
  if (/[A-Z]/.test(password)) score += 1;
  else issues.push('Sem letras maiúsculas');
  
  // Letras minúsculas
  if (/[a-z]/.test(password)) score += 1;
  else issues.push('Sem letras minúsculas');
  
  // Números
  if (/[0-9]/.test(password)) score += 1;
  else issues.push('Sem números');
  
  // Caracteres especiais
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
  else issues.push('Sem caracteres especiais');
  
  // Padrões comuns fracos
  const weakPatterns = [
    /^123/, /123$/, /password/i, /qwerty/i, /abc123/i,
    /admin/i, /letmein/i, /welcome/i, /monkey/i, /dragon/i
  ];
  if (weakPatterns.some(p => p.test(password))) {
    score -= 2;
    issues.push('Contém padrão comum');
  }
  
  // Sequências repetidas
  if (/(.)\1{2,}/.test(password)) {
    score -= 1;
    issues.push('Contém caracteres repetidos');
  }
  
  let strength: 'MUITO_FRACA' | 'FRACA' | 'MEDIA' | 'FORTE';
  if (score <= 1) strength = 'MUITO_FRACA';
  else if (score <= 3) strength = 'FRACA';
  else if (score <= 5) strength = 'MEDIA';
  else strength = 'FORTE';
  
  return { strength, issues };
}

/**
 * Agrupa credenciais por características
 */
function groupCredentials(credentials: HudsonRockCredential[]): {
  byMalware: Record<string, HudsonRockCredential[]>;
  byUrl: Record<string, HudsonRockCredential[]>;
  byDate: Record<string, HudsonRockCredential[]>;
  passwordAnalysis: {
    total: number;
    weak: number;
    medium: number;
    strong: number;
    reused: number;
  };
} {
  const byMalware: Record<string, HudsonRockCredential[]> = {};
  const byUrl: Record<string, HudsonRockCredential[]> = {};
  const byDate: Record<string, HudsonRockCredential[]> = {};
  const passwordCounts: Record<string, number> = {};
  
  let weakCount = 0;
  let mediumCount = 0;
  let strongCount = 0;
  
  credentials.forEach(cred => {
    // Por malware
    const malware = cred.malware_family || 'Unknown';
    if (!byMalware[malware]) byMalware[malware] = [];
    byMalware[malware].push(cred);
    
    // Por URL
    const url = cred.url || 'Unknown';
    if (!byUrl[url]) byUrl[url] = [];
    byUrl[url].push(cred);
    
    // Por data (mês/ano)
    const date = cred.date_compromised ? cred.date_compromised.substring(0, 7) : 'Unknown';
    if (!byDate[date]) byDate[date] = [];
    byDate[date].push(cred);
    
    // Análise de senha
    if (cred.password) {
      const analysis = analyzePasswordStrength(cred.password);
      if (analysis.strength === 'MUITO_FRACA' || analysis.strength === 'FRACA') weakCount++;
      else if (analysis.strength === 'MEDIA') mediumCount++;
      else strongCount++;
      
      // Contar reutilização
      const hash = cred.password.toLowerCase();
      passwordCounts[hash] = (passwordCounts[hash] || 0) + 1;
    }
  });
  
  const reusedCount = Object.values(passwordCounts).filter(c => c > 1).length;
  
  return {
    byMalware,
    byUrl,
    byDate,
    passwordAnalysis: {
      total: credentials.length,
      weak: weakCount,
      medium: mediumCount,
      strong: strongCount,
      reused: reusedCount
    }
  };
}

export async function buscarCredenciaisComprometidas(
  dominio: string,
  apiKey?: string
): Promise<ResultadoFonte> {
  const achados: AchadoCandidato[] = [];
  
  try {
    // Buscar por domínio
    const response = await axios.get<HudsonRockResponse>(
      `${HUDSON_ROCK_API}/search-by-domain`,
      {
        params: { domain: dominio },
        headers: apiKey ? { 'api-key': apiKey } : {},
        timeout: 30000,
      }
    );
    
    const data = response.data;
    
    if (data.stealers && data.stealers.length > 0) {
      const grouped = groupCredentials(data.stealers);
      
      // Criar achado para cada família de malware
      Object.entries(grouped.byMalware).forEach(([malware, credenciais]) => {
        const emailsUnicos = [...new Set(credenciais.map(c => c.email))];
        const urlsAfetadas = [...new Set(credenciais.map(c => c.url).filter(Boolean))];
        const ipsInfectados = [...new Set(credenciais.map(c => c.ip).filter(Boolean))];
        const computadores = [...new Set(credenciais.map(c => c.computer_name).filter(Boolean))];
        
        // Determinar data mais recente de comprometimento
        const datasComprometimento = credenciais
          .map(c => c.date_compromised)
          .filter(Boolean)
          .sort()
          .reverse();
        
        const dataRecente = datasComprometimento[0] || 'N/A';
        const dataAntiga = datasComprometimento[datasComprometimento.length - 1] || 'N/A';
        
        // Preparar lista de credenciais com senhas mascaradas
        const credenciaisDetalhadas = credenciais.slice(0, 20).map(c => ({
          email: c.email,
          username: c.username || c.email.split('@')[0],
          passwordMasked: maskPassword(c.password),
          passwordStrength: analyzePasswordStrength(c.password),
          url: c.url,
          dateCompromised: c.date_compromised,
          computerName: c.computer_name,
          ip: c.ip,
          os: c.operating_system
        }));
        
        // Infostealers são sempre críticos - credenciais comprometidas
        const nivelRisco = NivelRisco.CRITICO;
        
        const descricao = `Foram identificadas ${credenciais.length} credencial(is) comprometida(s) ` +
          `por infostealer "${malware}". ` +
          `E-mails afetados: ${emailsUnicos.length}. ` +
          `URLs com credenciais vazadas: ${urlsAfetadas.length}. ` +
          `Período: ${dataAntiga} a ${dataRecente}. ` +
          `IPs de máquinas infectadas: ${ipsInfectados.length}. ` +
          `Análise de senhas: ${grouped.passwordAnalysis.weak} fracas, ` +
          `${grouped.passwordAnalysis.reused} reutilizadas.`;
        
        achados.push({
          fonte: FonteInformacao.LEAKIX, // Usando LEAKIX como proxy para Hudson Rock
          nivelRisco,
          tipo: 'infostealer_credentials',
          tipoEntidade: TipoEntidade.DOMINIO,
          entidade: dominio,
          titulo: `Credenciais Comprometidas por Infostealer: ${malware}`,
          descricao,
          recomendacao: 'URGENTE: Credenciais foram roubadas por malware. Ações imediatas: ' +
            '1) Forçar reset de senha para todos os e-mails afetados; ' +
            '2) Revogar sessões ativas; ' +
            '3) Habilitar MFA em todas as contas; ' +
            '4) Investigar máquinas infectadas (IPs listados); ' +
            '5) Verificar acessos não autorizados nos sistemas; ' +
            '6) Comunicar à ANPD em até 3 dias úteis (Art. 48 LGPD).',
          evidencia: {
            malwareFamily: malware,
            totalCredenciais: credenciais.length,
            
            // Detalhes de credenciais (com senhas mascaradas)
            credenciaisDetalhadas,
            
            // Emails afetados
            emailsAfetados: emailsUnicos.slice(0, 30),
            totalEmails: emailsUnicos.length,
            
            // URLs onde credenciais foram usadas
            urlsAfetadas: urlsAfetadas.slice(0, 20),
            totalUrls: urlsAfetadas.length,
            
            // Máquinas infectadas
            ipsInfectados: ipsInfectados.slice(0, 15),
            totalIps: ipsInfectados.length,
            computadoresInfectados: computadores.slice(0, 15),
            totalComputadores: computadores.length,
            
            // Timeline
            dataComprometimentoRecente: dataRecente,
            dataComprometimentoAntiga: dataAntiga,
            timelineComprometimentos: Object.entries(grouped.byDate)
              .map(([date, creds]) => ({ date, count: creds.length }))
              .sort((a, b) => b.date.localeCompare(a.date))
              .slice(0, 12),
            
            // Análise de senhas
            analisesSenhas: {
              total: grouped.passwordAnalysis.total,
              fracas: grouped.passwordAnalysis.weak,
              medias: grouped.passwordAnalysis.medium,
              fortes: grouped.passwordAnalysis.strong,
              reutilizadas: grouped.passwordAnalysis.reused,
              percentualFracas: Math.round((grouped.passwordAnalysis.weak / grouped.passwordAnalysis.total) * 100)
            },
            
            // Sistemas operacionais e antivírus
            sistemasOperacionais: [...new Set(credenciais.map(c => c.operating_system).filter(Boolean))],
            antivirusDetectados: [...new Set(credenciais.flatMap(c => c.antiviruses || []))],
          },
        });
      });
      
      // Achado geral de resumo
      if (Object.keys(grouped.byMalware).length > 1) {
        const totalCredenciais = data.stealers.length;
        const totalEmails = [...new Set(data.stealers.map(c => c.email))].length;
        const familiasMalware = Object.keys(grouped.byMalware);
        
        achados.unshift({
          fonte: FonteInformacao.LEAKIX,
          nivelRisco: NivelRisco.CRITICO,
          tipo: 'infostealer_summary',
          tipoEntidade: TipoEntidade.DOMINIO,
          entidade: dominio,
          titulo: `CRÍTICO: ${totalCredenciais} Credenciais Comprometidas por ${familiasMalware.length} Famílias de Malware`,
          descricao: `O domínio ${dominio} teve ${totalCredenciais} credenciais comprometidas ` +
            `afetando ${totalEmails} e-mails únicos. ` +
            `Famílias de malware detectadas: ${familiasMalware.join(', ')}. ` +
            `${grouped.passwordAnalysis.weak} senhas são consideradas fracas. ` +
            `${grouped.passwordAnalysis.reused} senhas foram reutilizadas em múltiplos serviços.`,
          recomendacao: 'Implementar programa de resposta a incidentes de credenciais comprometidas. ' +
            'Considerar monitoramento contínuo de vazamentos e implementação de MFA obrigatório. ' +
            'Este incidente REQUER comunicação à ANPD conforme Art. 48 da LGPD.',
          evidencia: {
            totalCredenciais,
            totalEmailsUnicos: totalEmails,
            familiasMalware,
            totalFamilias: familiasMalware.length,
            analiseGlobalSenhas: grouped.passwordAnalysis,
            urlsMaisAfetadas: Object.entries(grouped.byUrl)
              .map(([url, creds]) => ({ url, count: creds.length }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 10),
            timelineGlobal: Object.entries(grouped.byDate)
              .map(([date, creds]) => ({ date, count: creds.length }))
              .sort((a, b) => b.date.localeCompare(a.date))
          },
        });
      }
    }
    
    return {
      achados,
      itensEncontrados: data.stealers?.length || 0,
      metadados: {
        fonte: 'Hudson Rock (Cavalier)',
        dominio,
        totalCredenciais: data.total_results || data.stealers?.length || 0,
      },
    };
  } catch (erro: any) {
    if (erro.response?.status === 404 || erro.response?.data?.message?.includes('No results')) {
      return {
        achados: [],
        itensEncontrados: 0,
        metadados: { fonte: 'Hudson Rock', dominio, status: 'sem_resultados' },
      };
    }
    throw erro;
  }
}

// Buscar por e-mail específico
export async function buscarCredenciaisPorEmail(
  email: string,
  apiKey?: string
): Promise<ResultadoFonte> {
  const achados: AchadoCandidato[] = [];
  
  try {
    const response = await axios.get<HudsonRockResponse>(
      `${HUDSON_ROCK_API}/search-by-email`,
      {
        params: { email },
        headers: apiKey ? { 'api-key': apiKey } : {},
        timeout: 30000,
      }
    );
    
    const data = response.data;
    
    if (data.stealers && data.stealers.length > 0) {
      const credencial = data.stealers[0];
      const passwordAnalysis = analyzePasswordStrength(credencial.password);
      
      achados.push({
        fonte: FonteInformacao.HIBP,
        nivelRisco: NivelRisco.CRITICO,
        tipo: 'email_infostealer',
        tipoEntidade: TipoEntidade.EMAIL,
        entidade: email,
        titulo: `E-mail Comprometido por Infostealer: ${credencial.malware_family}`,
        descricao: `O e-mail ${email} foi comprometido por malware "${credencial.malware_family}" ` +
          `em ${credencial.date_compromised || 'data desconhecida'}. ` +
          `Máquina infectada: ${credencial.computer_name || 'N/A'} (${credencial.operating_system || 'N/A'}). ` +
          `IP: ${credencial.ip || 'N/A'}. ` +
          `Força da senha: ${passwordAnalysis.strength}.`,
        recomendacao: 'Alterar senha imediatamente. Verificar se há acessos não autorizados. ' +
          'Habilitar autenticação de dois fatores. ' +
          'Verificar a máquina infectada e remover o malware.',
        evidencia: {
          email,
          username: credencial.username || email.split('@')[0],
          passwordMasked: maskPassword(credencial.password),
          passwordStrength: passwordAnalysis,
          malwareFamily: credencial.malware_family,
          dataComprometimento: credencial.date_compromised,
          computador: credencial.computer_name,
          sistemaOperacional: credencial.operating_system,
          ip: credencial.ip,
          antiviruses: credencial.antiviruses,
          urlsAfetadas: data.stealers.map(s => ({
            url: s.url,
            username: s.username,
            passwordMasked: maskPassword(s.password)
          })).filter(s => s.url),
          totalUrlsAfetadas: data.stealers.filter(s => s.url).length
        },
      });
    }
    
    return {
      achados,
      itensEncontrados: data.stealers?.length || 0,
      metadados: {
        fonte: 'Hudson Rock',
        email,
        comprometido: (data.stealers?.length || 0) > 0,
      },
    };
  } catch (erro: any) {
    if (erro.response?.status === 404) {
      return {
        achados: [],
        itensEncontrados: 0,
        metadados: { fonte: 'Hudson Rock', email, status: 'sem_resultados' },
      };
    }
    throw erro;
  }
}
