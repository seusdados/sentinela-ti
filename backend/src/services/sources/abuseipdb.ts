// ============================================================================
// SENTINELA - Fonte: AbuseIPDB (Base de Dados de IPs Abusivos)
// ============================================================================
// 
// O AbuseIPDB é uma base de dados colaborativa onde administradores de sistemas
// reportam IPs que realizaram atividades maliciosas. É amplamente usado para
// verificar se um IP está associado a ataques, spam ou outras atividades abusivas.
//
// UTILIDADE: Verificar se os IPs da empresa estão em listas de abuso:
// - IPs reportados por envio de spam
// - IPs usados em ataques de força bruta
// - IPs associados a botnets ou DDoS
// - Reputação geral do IP
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoAbuseIPDB {
  data?: {
    ipAddress: string;
    isPublic: boolean;
    ipVersion: number;
    isWhitelisted: boolean;
    abuseConfidenceScore: number;
    countryCode?: string;
    usageType?: string;
    isp?: string;
    domain?: string;
    hostnames?: string[];
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt?: string;
    reports?: {
      reportedAt: string;
      comment: string;
      categories: number[];
      reporterId: number;
      reporterCountryCode?: string;
    }[];
  };
}

// Mapeamento de categorias do AbuseIPDB
const CATEGORIAS_ABUSO: Record<number, string> = {
  1: 'Consulta DNS abusiva',
  2: 'Spam de DNS',
  3: 'Fraude de pedidos/vendas',
  4: 'Ataque DDoS',
  5: 'Ataque FTP',
  6: 'Ping da morte',
  7: 'Phishing',
  8: 'Spam de formulário',
  9: 'Email spam',
  10: 'SSH brute force',
  11: 'SQL injection',
  12: 'Spoofing',
  13: 'Ataque VoIP',
  14: 'Varredura de portas',
  15: 'Hacking genérico',
  16: 'Inclusão de arquivo remoto',
  17: 'Harvesting de emails',
  18: 'Força bruta',
  19: 'URL/blog spam',
  20: 'Raspagem de dados',
  21: 'Comprometimento de IoT',
  22: 'Exploração web',
  23: 'Bad web bot',
};

export async function verificarReputacaoIP(ip: string, chaveApi: string): Promise<ResultadoFonte> {
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`;
  
  const resposta = await http.get<ResultadoAbuseIPDB>(url, {
    headers: {
      'Key': chaveApi,
      'Accept': 'application/json',
    },
  });
  
  if (!resposta.sucesso) {
    throw new Error(resposta.erro?.mensagem || 'Erro ao consultar AbuseIPDB');
  }
  
  const dados = resposta.dados?.data;
  
  if (!dados) {
    return {
      achados: [],
      itensEncontrados: 0,
      metadados: { ip, semDados: true },
    };
  }
  
  const achados: AchadoCandidato[] = [];
  const pontuacaoConfianca = dados.abuseConfidenceScore || 0;
  const totalReportes = dados.totalReports || 0;
  const usuariosDistintos = dados.numDistinctUsers || 0;
  
  if (pontuacaoConfianca > 0 || totalReportes > 0) {
    // Determinar nível de risco baseado na pontuação
    let nivelRisco = NivelRisco.BAIXO;
    let tipo = 'ip_reportado';
    
    if (pontuacaoConfianca >= 80) {
      nivelRisco = NivelRisco.CRITICO;
      tipo = 'ip_altamente_abusivo';
    } else if (pontuacaoConfianca >= 50) {
      nivelRisco = NivelRisco.ALTO;
      tipo = 'ip_abusivo';
    } else if (pontuacaoConfianca >= 25) {
      nivelRisco = NivelRisco.MEDIO;
      tipo = 'ip_suspeito';
    }
    
    // Coletar categorias de abuso reportadas
    const categoriasReportadas = new Set<string>();
    if (dados.reports) {
      for (const reporte of dados.reports) {
        for (const catId of reporte.categories) {
          const categoria = CATEGORIAS_ABUSO[catId];
          if (categoria) {
            categoriasReportadas.add(categoria);
          }
        }
      }
    }
    
    // Construir descrição
    let descricao = `O endereço IP ${ip} possui uma pontuação de confiança de abuso de ${pontuacaoConfianca}% no AbuseIPDB. `;
    descricao += `Ele foi reportado ${totalReportes} vez(es) por ${usuariosDistintos} usuário(s) distinto(s) nos últimos 90 dias. `;
    
    if (categoriasReportadas.size > 0) {
      descricao += `Tipos de abuso reportados: ${[...categoriasReportadas].join(', ')}. `;
    }
    
    if (dados.isp) {
      descricao += `ISP: ${dados.isp}. `;
    }
    
    if (dados.lastReportedAt) {
      const ultimoReporte = new Date(dados.lastReportedAt);
      descricao += `Último reporte: ${ultimoReporte.toLocaleDateString('pt-BR')}.`;
    }
    
    // Construir recomendação
    let recomendacao = '';
    if (nivelRisco === NivelRisco.CRITICO) {
      recomendacao = 'URGENTE: Este IP possui reputação extremamente negativa. Se pertence à sua organização, investigue imediatamente possível comprometimento. Se é um IP externo acessando seus sistemas, bloqueie-o no firewall.';
    } else if (nivelRisco === NivelRisco.ALTO) {
      recomendacao = 'Este IP tem histórico significativo de atividades abusivas. Verifique os logs de acesso para identificar atividades suspeitas e considere implementar bloqueios ou monitoramento adicional.';
    } else if (nivelRisco === NivelRisco.MEDIO) {
      recomendacao = 'Monitore o tráfego relacionado a este IP. Os reportes podem indicar comportamento legítimo mal interpretado ou uma ameaça real.';
    } else {
      recomendacao = 'IP com poucos reportes. Monitore normalmente e verifique se há padrões suspeitos nos logs de acesso.';
    }
    
    achados.push({
      fonte: FonteInformacao.ABUSEIPDB,
      nivelRisco,
      tipo,
      tipoEntidade: TipoEntidade.IP,
      entidade: ip,
      titulo: `IP ${ip} com ${pontuacaoConfianca}% de pontuação de abuso`,
      descricao,
      recomendacao,
      evidencia: {
        ip,
        pontuacaoConfianca,
        totalReportes,
        usuariosDistintos,
        categorias: [...categoriasReportadas],
        isp: dados.isp,
        pais: dados.countryCode,
        tipoUso: dados.usageType,
        hostnames: dados.hostnames,
        ultimoReporte: dados.lastReportedAt,
        reportesRecentes: dados.reports?.slice(0, 5).map(r => ({
          data: r.reportedAt,
          comentario: r.comment?.slice(0, 200),
          categorias: r.categories.map(c => CATEGORIAS_ABUSO[c] || `Categoria ${c}`),
        })),
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: totalReportes,
    metadados: {
      ip,
      pontuacaoConfianca,
      totalReportes,
      naListaBranca: dados.isWhitelisted,
    },
  };
}
