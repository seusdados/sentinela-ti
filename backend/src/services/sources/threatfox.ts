// ============================================================================
// SENTINELA - Integração com Abuse.ch ThreatFox
// Detecta Indicadores de Comprometimento (IoCs) de malware
// API: https://threatfox-api.abuse.ch/api/v1/
// ============================================================================

import axios from 'axios';
import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { AchadoCandidato, ResultadoFonte } from '../../types';

const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';

interface ThreatFoxIOC {
  id: string;
  ioc: string;
  ioc_type: string;
  threat_type: string;
  malware: string;
  malware_printable: string;
  malware_alias: string | null;
  malware_malpedia: string | null;
  confidence_level: number;
  first_seen: string;
  last_seen: string;
  reporter: string;
  reference: string | null;
  tags: string[];
}

interface ThreatFoxResponse {
  query_status: string;
  data?: ThreatFoxIOC[];
}

export async function buscarIndicadoresMalware(dominio: string): Promise<ResultadoFonte> {
  const achados: AchadoCandidato[] = [];
  
  try {
    // Buscar IoCs relacionados ao domínio
    const response = await axios.post<ThreatFoxResponse>(
      THREATFOX_API,
      {
        query: 'search_ioc',
        search_term: dominio,
      },
      {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 30000,
      }
    );
    
    const data = response.data;
    
    if (data.query_status === 'ok' && data.data && data.data.length > 0) {
      // Agrupar por malware
      const iocsPorMalware: Record<string, ThreatFoxIOC[]> = {};
      
      data.data.forEach(ioc => {
        const malware = ioc.malware_printable || ioc.malware || 'unknown';
        if (!iocsPorMalware[malware]) {
          iocsPorMalware[malware] = [];
        }
        iocsPorMalware[malware].push(ioc);
      });
      
      // Criar achado para cada família de malware
      Object.entries(iocsPorMalware).forEach(([malware, iocs]) => {
        // Determinar severidade baseada no tipo de ameaça e confiança
        const avgConfidence = iocs.reduce((sum, i) => sum + i.confidence_level, 0) / iocs.length;
        const threatTypes = [...new Set(iocs.map(i => i.threat_type.toLowerCase()))];
        
        // Ransomware/Stealer = CRITICO, senão ALTO (mantemos ALTO para IoCs de malware)
        const nivelRisco = threatTypes.some(t => t.includes('ransomware') || t.includes('stealer'))
          ? NivelRisco.CRITICO
          : NivelRisco.ALTO;
        
        const tiposIoc = [...new Set(iocs.map(i => i.ioc_type))];
        const tags = [...new Set(iocs.flatMap(i => i.tags))];
        
        const descricao = `Foram identificados ${iocs.length} Indicador(es) de Comprometimento (IoC) ` +
          `associados à família de malware "${malware}". ` +
          `Tipos de IoC: ${tiposIoc.join(', ')}. ` +
          `Tipos de ameaça: ${threatTypes.join(', ')}. ` +
          `Nível de confiança médio: ${avgConfidence.toFixed(0)}%.`;
        
        achados.push({
          fonte: FonteInformacao.OTX, // Usando OTX como proxy para ThreatFox
          nivelRisco,
          tipo: 'malware_ioc',
          tipoEntidade: TipoEntidade.DOMINIO,
          entidade: dominio,
          titulo: `IoCs de Malware: ${malware}`,
          descricao,
          recomendacao: threatTypes.some(t => t.includes('ransomware') || t.includes('stealer'))
            ? 'CRÍTICO: IoCs de malware de alto risco detectados. Execute varredura completa de endpoints, verifique logs de rede e considere resposta a incidentes.'
            : 'Investigue a presença dos IoCs identificados em sua infraestrutura. Atualize regras de firewall e EDR.',
          evidencia: {
            malware,
            malwareAlias: iocs[0].malware_alias,
            malwareMalpedia: iocs[0].malware_malpedia,
            totalIocs: iocs.length,
            tiposIoc,
            tiposAmeaca: threatTypes,
            confiancaMedia: avgConfidence,
            tags,
            primeiraVez: iocs.reduce((min, i) => i.first_seen < min ? i.first_seen : min, iocs[0].first_seen),
            ultimaVez: iocs.reduce((max, i) => i.last_seen > max ? i.last_seen : max, iocs[0].last_seen),
            exemplosIocs: iocs.slice(0, 5).map(i => ({
              ioc: i.ioc,
              tipo: i.ioc_type,
              confianca: i.confidence_level,
              referencia: i.reference,
            })),
          },
        });
      });
    }
    
    return {
      achados,
      itensEncontrados: achados.length,
      metadados: {
        fonte: 'ThreatFox (Abuse.ch)',
        dominio,
        totalIocsEncontrados: data.data?.length || 0,
      },
    };
  } catch (erro: any) {
    if (erro.response?.status === 404 || erro.response?.data?.query_status === 'no_results') {
      return {
        achados: [],
        itensEncontrados: 0,
        metadados: { fonte: 'ThreatFox', dominio, status: 'sem_resultados' },
      };
    }
    throw erro;
  }
}
