// ============================================================================
// SENTINELA - Fonte: VirusTotal (Análise de Reputação de Domínios)
// ============================================================================
// 
// O VirusTotal é uma plataforma que agrega resultados de mais de 70 motores
// antivírus e serviços de análise de URLs. Quando um domínio é verificado,
// o VirusTotal consulta todos esses motores para determinar se há indicações
// de atividade maliciosa.
//
// UTILIDADE: Verificar a reputação do domínio da empresa:
// - Detecções de malware associado ao domínio
// - Indicações de phishing
// - Histórico de atividades suspeitas
// - Categorização do domínio por diferentes vendors
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoVirusTotal {
  data?: {
    id: string;
    type: string;
    attributes?: {
      last_analysis_stats?: {
        harmless: number;
        malicious: number;
        suspicious: number;
        undetected: number;
        timeout: number;
      };
      last_analysis_results?: Record<string, {
        category: string;
        result: string;
        method: string;
        engine_name: string;
      }>;
      reputation?: number;
      categories?: Record<string, string>;
      last_analysis_date?: number;
      last_dns_records?: {
        type: string;
        value: string;
      }[];
      whois?: string;
    };
  };
}

export async function verificarReputacao(dominio: string, chaveApi: string): Promise<ResultadoFonte> {
  const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(dominio)}`;
  
  const resposta = await http.get<ResultadoVirusTotal>(url, {
    headers: { 'x-apikey': chaveApi },
  });
  
  if (!resposta.sucesso) {
    throw new Error(resposta.erro?.mensagem || 'Erro ao consultar VirusTotal');
  }
  
  const atributos = resposta.dados?.data?.attributes;
  const estatisticas = atributos?.last_analysis_stats;
  
  if (!estatisticas) {
    return {
      achados: [],
      itensEncontrados: 0,
      metadados: { dominio, semDados: true },
    };
  }
  
  const achados: AchadoCandidato[] = [];
  const maliciosos = estatisticas.malicious || 0;
  const suspeitos = estatisticas.suspicious || 0;
  const reputacao = atributos?.reputation || 0;
  
  // Coletar detalhes das detecções
  const detecoesMaliciosas: string[] = [];
  const detecoesSuspeitas: string[] = [];
  
  if (atributos?.last_analysis_results) {
    for (const [engine, resultado] of Object.entries(atributos.last_analysis_results)) {
      if (resultado.category === 'malicious') {
        detecoesMaliciosas.push(`${engine}: ${resultado.result || 'malicioso'}`);
      } else if (resultado.category === 'suspicious') {
        detecoesSuspeitas.push(`${engine}: ${resultado.result || 'suspeito'}`);
      }
    }
  }
  
  // Criar achado se houver detecções negativas
  if (maliciosos > 0 || suspeitos > 0) {
    const nivelRisco = maliciosos > 5 ? NivelRisco.CRITICO 
                      : maliciosos > 0 ? NivelRisco.ALTO 
                      : NivelRisco.MEDIO;
    
    let titulo = '';
    let descricao = '';
    let recomendacao = '';
    
    if (maliciosos > 5) {
      titulo = `CRÍTICO: Domínio ${dominio} marcado como malicioso por múltiplos antivírus`;
      descricao = `O domínio ${dominio} foi identificado como malicioso por ${maliciosos} motor(es) de segurança e como suspeito por ${suspeitos}. Esta é uma indicação forte de que o domínio pode estar comprometido, sendo usado para distribuição de malware, phishing ou outras atividades maliciosas. Engines que detectaram: ${detecoesMaliciosas.slice(0, 5).join('; ')}${detecoesMaliciosas.length > 5 ? '...' : ''}`;
      recomendacao = 'URGENTE: Investigue imediatamente o domínio. Verifique se o servidor foi comprometido, analise logs de acesso, escaneie por malware e considere a possibilidade de que credenciais foram vazadas. Pode ser necessário notificar clientes e usuários.';
    } else if (maliciosos > 0) {
      titulo = `Domínio ${dominio} com detecções de segurança no VirusTotal`;
      descricao = `O domínio ${dominio} foi marcado como malicioso por ${maliciosos} motor(es) e como suspeito por ${suspeitos} no VirusTotal. Isso pode indicar um problema de segurança ou um falso positivo. Detecções: ${[...detecoesMaliciosas, ...detecoesSuspeitas].slice(0, 5).join('; ')}`;
      recomendacao = 'Investigue as detecções reportadas. Verifique se há malware no servidor, analise o conteúdo do site e, se for um falso positivo, solicite revisão aos vendors que detectaram o problema.';
    } else {
      titulo = `Domínio ${dominio} com indicações suspeitas no VirusTotal`;
      descricao = `O domínio ${dominio} foi marcado como suspeito por ${suspeitos} motor(es) de segurança. Embora não seja uma detecção definitiva, isso merece atenção. Detecções: ${detecoesSuspeitas.slice(0, 5).join('; ')}`;
      recomendacao = 'Monitore o domínio e verifique se há comportamentos incomuns. Considere uma análise mais aprofundada do servidor e do conteúdo hospedado.';
    }
    
    achados.push({
      fonte: FonteInformacao.VIRUSTOTAL,
      nivelRisco,
      tipo: 'reputacao_dominio',
      tipoEntidade: TipoEntidade.DOMINIO,
      entidade: dominio,
      titulo,
      descricao,
      recomendacao,
      evidencia: {
        estatisticas,
        reputacao,
        detecoesMaliciosas: detecoesMaliciosas.slice(0, 10),
        detecoesSuspeitas: detecoesSuspeitas.slice(0, 10),
        categorias: atributos?.categories,
        ultimaAnalise: atributos?.last_analysis_date 
          ? new Date(atributos.last_analysis_date * 1000).toISOString() 
          : undefined,
      },
    });
  }
  
  // Verificar reputação muito negativa mesmo sem detecções atuais
  if (reputacao < -10 && maliciosos === 0) {
    achados.push({
      fonte: FonteInformacao.VIRUSTOTAL,
      nivelRisco: NivelRisco.MEDIO,
      tipo: 'reputacao_negativa',
      tipoEntidade: TipoEntidade.DOMINIO,
      entidade: dominio,
      titulo: `Domínio ${dominio} com reputação negativa no VirusTotal`,
      descricao: `Embora não haja detecções maliciosas atuais, o domínio ${dominio} possui uma pontuação de reputação negativa (${reputacao}) no VirusTotal. Isso pode indicar um histórico de problemas de segurança ou associação com atividades suspeitas no passado.`,
      recomendacao: 'Investigue o histórico do domínio e verifique se há motivos para a reputação negativa. Considere implementar medidas adicionais de segurança e monitoramento.',
      evidencia: {
        reputacao,
        estatisticas,
        categorias: atributos?.categories,
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: achados.length,
    metadados: {
      estatisticas,
      reputacao,
      totalMotores: (estatisticas.harmless || 0) + (estatisticas.malicious || 0) + 
                    (estatisticas.suspicious || 0) + (estatisticas.undetected || 0),
      categorias: atributos?.categories,
    },
  };
}
