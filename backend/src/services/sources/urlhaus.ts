// ============================================================================
// SENTINELA - Integração com Abuse.ch URLhaus
// Detecta URLs maliciosas associadas a malware
// API: https://urlhaus-api.abuse.ch/v1/
// ============================================================================

import axios from 'axios';
import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { AchadoCandidato, ResultadoFonte } from '../../types';

const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1';

interface URLHausPayload {
  query_status: string;
  urls?: {
    id: string;
    url: string;
    url_status: string;
    date_added: string;
    threat: string;
    tags: string[];
    urlhaus_reference: string;
    reporter: string;
  }[];
  host?: string;
}

export async function buscarURLsMaliciosas(dominio: string): Promise<ResultadoFonte> {
  const achados: AchadoCandidato[] = [];
  
  try {
    // Buscar por host/domínio
    const response = await axios.post<URLHausPayload>(
      `${URLHAUS_API}/host/`,
      `host=${encodeURIComponent(dominio)}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 30000,
      }
    );
    
    const data = response.data;
    
    if (data.query_status === 'ok' && data.urls && data.urls.length > 0) {
      // Agrupar por threat type
      const urlsPorThreat: Record<string, typeof data.urls> = {};
      
      data.urls.forEach(url => {
        const threat = url.threat || 'unknown';
        if (!urlsPorThreat[threat]) {
          urlsPorThreat[threat] = [];
        }
        urlsPorThreat[threat].push(url);
      });
      
      // Criar achado para cada tipo de ameaça
      Object.entries(urlsPorThreat).forEach(([threat, urls]) => {
        const urlsAtivas = urls.filter(u => u.url_status === 'online');
        const urlsOffline = urls.filter(u => u.url_status !== 'online');
        
        // Determinar severidade baseada no tipo de ameaça e status
        // Ransomware ou URLs ativas = CRITICO, senão ALTO
        const nivelRisco = threat.toLowerCase().includes('ransomware') || urlsAtivas.length > 0
          ? NivelRisco.CRITICO
          : NivelRisco.ALTO;
        
        const descricao = `Foram identificadas ${urls.length} URL(s) maliciosas associadas ao domínio ${dominio}. ` +
          `Tipo de ameaça: ${threat}. ` +
          `URLs ativas: ${urlsAtivas.length}. URLs offline: ${urlsOffline.length}. ` +
          `Tags: ${[...new Set(urls.flatMap(u => u.tags))].join(', ') || 'N/A'}.`;
        
        achados.push({
          fonte: FonteInformacao.URLSCAN, // Usando URLSCAN como proxy para URLhaus
          nivelRisco,
          tipo: 'malware_url',
          tipoEntidade: TipoEntidade.DOMINIO,
          entidade: dominio,
          titulo: `URLs de Malware Detectadas (${threat})`,
          descricao,
          recomendacao: urlsAtivas.length > 0
            ? 'URGENTE: Existem URLs maliciosas ATIVAS associadas ao seu domínio. Investigue imediatamente a origem, verifique se há comprometimento de servidores e solicite remoção das URLs.'
            : 'URLs maliciosas foram associadas ao seu domínio no passado. Verifique logs históricos e garanta que não há comprometimento residual.',
          evidencia: {
            totalUrls: urls.length,
            urlsAtivas: urlsAtivas.length,
            urlsOffline: urlsOffline.length,
            tipoAmeaca: threat,
            tags: [...new Set(urls.flatMap(u => u.tags))],
            primeiraDeteccao: urls.reduce((min, u) => u.date_added < min ? u.date_added : min, urls[0].date_added),
            ultimaDeteccao: urls.reduce((max, u) => u.date_added > max ? u.date_added : max, urls[0].date_added),
            exemplosUrls: urls.slice(0, 5).map(u => ({
              url: u.url,
              status: u.url_status,
              dataAdicao: u.date_added,
              referencia: u.urlhaus_reference,
            })),
          },
        });
      });
    }
    
    return {
      achados,
      itensEncontrados: achados.length,
      metadados: {
        fonte: 'URLhaus (Abuse.ch)',
        dominio,
        totalUrlsEncontradas: data.urls?.length || 0,
      },
    };
  } catch (erro: any) {
    if (erro.response?.status === 404 || erro.response?.data?.query_status === 'no_results') {
      return {
        achados: [],
        itensEncontrados: 0,
        metadados: { fonte: 'URLhaus', dominio, status: 'sem_resultados' },
      };
    }
    throw erro;
  }
}
