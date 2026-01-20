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
      // Agrupar por família de malware
      const porMalware: Record<string, HudsonRockCredential[]> = {};
      
      data.stealers.forEach(cred => {
        const malware = cred.malware_family || 'Unknown';
        if (!porMalware[malware]) {
          porMalware[malware] = [];
        }
        porMalware[malware].push(cred);
      });
      
      // Criar achado para cada família de malware
      Object.entries(porMalware).forEach(([malware, credenciais]) => {
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
        
        // Infostealers são sempre críticos - credenciais comprometidas
        const nivelRisco = NivelRisco.CRITICO;
        
        const descricao = `Foram identificadas ${credenciais.length} credencial(is) comprometida(s) ` +
          `por infostealer "${malware}". ` +
          `E-mails afetados: ${emailsUnicos.length}. ` +
          `URLs com credenciais vazadas: ${urlsAfetadas.length}. ` +
          `Período: ${dataAntiga} a ${dataRecente}. ` +
          `IPs de máquinas infectadas: ${ipsInfectados.length}.`;
        
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
            '4) Investigar máquinas infectadas; ' +
            '5) Verificar acessos não autorizados nos sistemas.',
          evidencia: {
            malwareFamily: malware,
            totalCredenciais: credenciais.length,
            emailsAfetados: emailsUnicos.slice(0, 20), // Limitar para não expor demais
            totalEmails: emailsUnicos.length,
            urlsAfetadas: urlsAfetadas.slice(0, 10),
            totalUrls: urlsAfetadas.length,
            ipsInfectados: ipsInfectados.slice(0, 10),
            totalIps: ipsInfectados.length,
            computadoresInfectados: computadores.slice(0, 10),
            totalComputadores: computadores.length,
            dataComprometimentoRecente: dataRecente,
            dataComprometimentoAntiga: dataAntiga,
            sistemasOperacionais: [...new Set(credenciais.map(c => c.operating_system).filter(Boolean))],
            antivirusDetectados: [...new Set(credenciais.flatMap(c => c.antiviruses || []))],
          },
        });
      });
      
      // Achado geral de resumo
      if (Object.keys(porMalware).length > 1) {
        const totalCredenciais = data.stealers.length;
        const totalEmails = [...new Set(data.stealers.map(c => c.email))].length;
        const familiasMalware = Object.keys(porMalware);
        
        achados.unshift({
          fonte: FonteInformacao.LEAKIX,
          nivelRisco: NivelRisco.CRITICO,
          tipo: 'infostealer_summary',
          tipoEntidade: TipoEntidade.DOMINIO,
          entidade: dominio,
          titulo: `Resumo: ${totalCredenciais} Credenciais Comprometidas por ${familiasMalware.length} Famílias de Malware`,
          descricao: `O domínio ${dominio} teve ${totalCredenciais} credenciais comprometidas ` +
            `afetando ${totalEmails} e-mails únicos. ` +
            `Famílias de malware detectadas: ${familiasMalware.join(', ')}.`,
          recomendacao: 'Implementar programa de resposta a incidentes de credenciais comprometidas. ' +
            'Considerar monitoramento contínuo de vazamentos e implementação de MFA obrigatório.',
          evidencia: {
            totalCredenciais,
            totalEmailsUnicos: totalEmails,
            familiasMalware,
            totalFamilias: familiasMalware.length,
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
      
      achados.push({
        fonte: FonteInformacao.HIBP,
        nivelRisco: NivelRisco.CRITICO,
        tipo: 'email_infostealer',
        tipoEntidade: TipoEntidade.EMAIL,
        entidade: email,
        titulo: `E-mail Comprometido por Infostealer: ${credencial.malware_family}`,
        descricao: `O e-mail ${email} foi comprometido por malware "${credencial.malware_family}" ` +
          `em ${credencial.date_compromised || 'data desconhecida'}. ` +
          `Máquina infectada: ${credencial.computer_name || 'N/A'} (${credencial.operating_system || 'N/A'}).`,
        recomendacao: 'Alterar senha imediatamente. Verificar se há acessos não autorizados. ' +
          'Habilitar autenticação de dois fatores.',
        evidencia: {
          email,
          malwareFamily: credencial.malware_family,
          dataComprometimento: credencial.date_compromised,
          computador: credencial.computer_name,
          sistemaOperacional: credencial.operating_system,
          ip: credencial.ip,
          urlsAfetadas: data.stealers.map(s => s.url).filter(Boolean),
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
