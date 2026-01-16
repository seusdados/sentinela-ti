// ============================================================================
// SENTINELA - Fonte: AlienVault OTX (Open Threat Exchange)
// ============================================================================
// 
// O AlienVault OTX é uma plataforma colaborativa de inteligência de ameaças
// onde pesquisadores de segurança compartilham indicadores de comprometimento
// (IOCs) em "pulses" - relatórios sobre ameaças específicas.
//
// UTILIDADE: Verificar se o domínio está associado a ameaças conhecidas:
// - Domínios usados em campanhas de malware
// - Infraestrutura de comando e controle (C2)
// - Associação com grupos de ameaças (APTs)
// - Indicadores de comprometimento históricos
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoOTX {
  pulse_info?: {
    count: number;
    pulses?: {
      id: string;
      name: string;
      description?: string;
      author_name?: string;
      created?: string;
      modified?: string;
      tags?: string[];
      references?: string[];
      adversary?: string;
      targeted_countries?: string[];
      industries?: string[];
      TLP?: string;
    }[];
    references?: string[];
  };
  general?: {
    whois?: string;
    alexa?: string;
  };
}

export async function buscarIndicadoresAmeaca(dominio: string, chaveApi?: string | null): Promise<ResultadoFonte> {
  const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(dominio)}/general`;
  
  const headers: Record<string, string> = {};
  if (chaveApi) {
    headers['X-OTX-API-KEY'] = chaveApi;
  }
  
  const resposta = await http.get<ResultadoOTX>(url, { headers });
  
  if (!resposta.sucesso) {
    throw new Error(resposta.erro?.mensagem || 'Erro ao consultar AlienVault OTX');
  }
  
  const dados = resposta.dados;
  const infoPulses = dados?.pulse_info;
  const totalPulses = infoPulses?.count || 0;
  const pulses = infoPulses?.pulses || [];
  
  const achados: AchadoCandidato[] = [];
  
  if (totalPulses > 0) {
    // Analisar os pulses para determinar a gravidade
    const pulsesRelevantes = pulses.slice(0, 10);
    const tags = new Set<string>();
    const adversarios = new Set<string>();
    const referencias: string[] = [];
    
    for (const pulse of pulsesRelevantes) {
      if (pulse.tags) {
        pulse.tags.forEach(t => tags.add(t.toLowerCase()));
      }
      if (pulse.adversary) {
        adversarios.add(pulse.adversary);
      }
      if (pulse.references) {
        referencias.push(...pulse.references.slice(0, 3));
      }
    }
    
    // Determinar nível de risco baseado nos tags e quantidade de pulses
    let nivelRisco = NivelRisco.MEDIO;
    let tipo = 'indicador_ameaca';
    
    const tagsAltoRisco = ['apt', 'ransomware', 'c2', 'c&c', 'botnet', 'trojan', 'malware'];
    const temTagAltoRisco = tagsAltoRisco.some(t => tags.has(t));
    
    if (adversarios.size > 0 || temTagAltoRisco) {
      nivelRisco = NivelRisco.ALTO;
      tipo = 'associacao_ameaca_conhecida';
    }
    
    if (totalPulses > 10) {
      nivelRisco = NivelRisco.CRITICO;
    }
    
    // Construir descrição detalhada
    let descricao = `O domínio ${dominio} aparece em ${totalPulses} pulse(s) de inteligência de ameaças no AlienVault OTX. `;
    
    if (adversarios.size > 0) {
      descricao += `O domínio foi associado ao(s) seguinte(s) grupo(s) de ameaça: ${[...adversarios].join(', ')}. `;
    }
    
    if (tags.size > 0) {
      const tagsList = [...tags].slice(0, 10).join(', ');
      descricao += `Tags relacionadas: ${tagsList}. `;
    }
    
    descricao += `Pulses são relatórios de ameaças criados por pesquisadores de segurança indicando que este domínio foi observado em atividades maliciosas ou é considerado um indicador de comprometimento.`;
    
    let recomendacao = '';
    if (nivelRisco === NivelRisco.CRITICO) {
      recomendacao = 'URGENTE: O alto número de associações com ameaças indica que este domínio pode estar seriamente comprometido ou sendo usado ativamente em campanhas maliciosas. Realize uma investigação forense completa, verifique todos os sistemas conectados e considere a possibilidade de incidente de segurança.';
    } else if (nivelRisco === NivelRisco.ALTO) {
      recomendacao = 'Investigue as associações reportadas. Verifique os logs do servidor para atividades suspeitas, analise o tráfego de rede e confirme se o domínio não está sendo usado para fins maliciosos.';
    } else {
      recomendacao = 'Monitore o domínio e revise periodicamente os pulses associados. Pode ser um falso positivo ou uma associação histórica já resolvida.';
    }
    
    achados.push({
      fonte: FonteInformacao.OTX,
      nivelRisco,
      tipo,
      tipoEntidade: TipoEntidade.DOMINIO,
      entidade: dominio,
      titulo: `Domínio ${dominio} citado em ${totalPulses} pulse(s) de inteligência de ameaças`,
      descricao,
      recomendacao,
      evidencia: {
        totalPulses,
        adversarios: [...adversarios],
        tags: [...tags].slice(0, 20),
        referencias: referencias.slice(0, 10),
        pulsesResumo: pulsesRelevantes.map(p => ({
          nome: p.name,
          autor: p.author_name,
          criado: p.created,
          tags: p.tags?.slice(0, 5),
          adversario: p.adversary,
        })),
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: totalPulses,
    metadados: {
      totalPulses,
      referencias: infoPulses?.references?.slice(0, 5),
    },
  };
}
