// ============================================================================
// SENTINELA - Serviço de Cálculo de Score de Risco
// Calcula pontuação de risco 0-100 baseada nos achados
// ============================================================================

import { NivelRisco, FonteInformacao } from '@prisma/client';

export interface AchadoParaScore {
  nivelRisco: NivelRisco;
  fonte: FonteInformacao;
  tipo: string;
  confianca?: number; // 0-100
}

export interface ScoreRisco {
  pontuacao: number; // 0-100
  classificacao: 'MINIMO' | 'BAIXO' | 'MEDIO' | 'ALTO' | 'CRITICO';
  cor: string;
  descricao: string;
  detalhes: {
    pontosPorSeveridade: {
      critico: number;
      alto: number;
      medio: number;
      baixo: number;
      informativo: number;
    };
    multiplicadorConfianca: number;
    bonusNegativo: number;
  };
  recomendacaoPrincipal: string;
}

// Pesos por nível de risco
const PESOS_RISCO: Record<NivelRisco, number> = {
  [NivelRisco.CRITICO]: 25,
  [NivelRisco.ALTO]: 15,
  [NivelRisco.MEDIO]: 8,
  [NivelRisco.BAIXO]: 3,
  [NivelRisco.INFORMATIVO]: 1,
};

// Multiplicadores de confiança por fonte
const CONFIANCA_FONTE: Record<FonteInformacao, number> = {
  [FonteInformacao.HIBP]: 1.0,        // Alta confiança - dados verificados
  [FonteInformacao.SHODAN]: 0.95,     // Alta confiança - dados técnicos
  [FonteInformacao.VIRUSTOTAL]: 0.95, // Alta confiança - múltiplos engines
  [FonteInformacao.LEAKIX]: 0.9,      // Alta confiança - vazamentos reais
  [FonteInformacao.CRTSH]: 0.85,      // Média-alta - dados públicos
  [FonteInformacao.URLSCAN]: 0.85,    // Média-alta - análise automatizada
  [FonteInformacao.OTX]: 0.8,         // Média - comunidade
  [FonteInformacao.ABUSEIPDB]: 0.8,   // Média - reports de comunidade
  [FonteInformacao.PSBDMP]: 0.75,     // Média - pode ter falsos positivos
  [FonteInformacao.GITHUB]: 0.7,      // Média-baixa - pode ser intencional
  [FonteInformacao.GOOGLE_DORKS]: 0.65, // Baixa - requer validação
  [FonteInformacao.INTELX]: 0.85,     // Média-alta - dados de inteligência
};

// Tipos de achados que aumentam significativamente o risco
const TIPOS_CRITICOS = [
  'ransomware_victim',
  'infostealer_credentials',
  'cve_critica',
  'banco_dados',
  'vulnerabilidades_detectadas',
  'malware_ioc',
];

const TIPOS_ALTO_IMPACTO = [
  'infostealer_summary',
  'cve_explorada',
  'servicos_alto_risco',
  'painel_administrativo',
  'acesso_remoto',
  'sistema_pagamento',
  'autenticacao',
];

export function calcularScoreRisco(achados: AchadoParaScore[]): ScoreRisco {
  if (achados.length === 0) {
    return {
      pontuacao: 0,
      classificacao: 'MINIMO',
      cor: '#22c55e', // Verde
      descricao: 'Nenhuma ameaça identificada nas fontes consultadas.',
      detalhes: {
        pontosPorSeveridade: { critico: 0, alto: 0, medio: 0, baixo: 0, informativo: 0 },
        multiplicadorConfianca: 1,
        bonusNegativo: 0,
      },
      recomendacaoPrincipal: 'Continue monitorando regularmente.',
    };
  }
  
  // Contar achados por severidade
  const contagem = {
    critico: 0,
    alto: 0,
    medio: 0,
    baixo: 0,
    informativo: 0,
  };
  
  let pontuacaoBruta = 0;
  let somaConfianca = 0;
  let bonusCritico = 0;
  
  achados.forEach(achado => {
    const peso = PESOS_RISCO[achado.nivelRisco];
    const confiancaFonte = CONFIANCA_FONTE[achado.fonte] || 0.7;
    const confiancaAchado = achado.confianca !== undefined ? achado.confianca / 100 : 1;
    const multiplicador = confiancaFonte * confiancaAchado;
    
    pontuacaoBruta += peso * multiplicador;
    somaConfianca += multiplicador;
    
    // Contagem por severidade
    switch (achado.nivelRisco) {
      case NivelRisco.CRITICO:
        contagem.critico++;
        break;
      case NivelRisco.ALTO:
        contagem.alto++;
        break;
      case NivelRisco.MEDIO:
        contagem.medio++;
        break;
      case NivelRisco.BAIXO:
        contagem.baixo++;
        break;
      case NivelRisco.INFORMATIVO:
        contagem.informativo++;
        break;
    }
    
    // Bonus para tipos críticos
    if (TIPOS_CRITICOS.includes(achado.tipo)) {
      bonusCritico += 10;
    } else if (TIPOS_ALTO_IMPACTO.includes(achado.tipo)) {
      bonusCritico += 5;
    }
  });
  
  // Calcular multiplicador médio de confiança
  const multiplicadorConfianca = achados.length > 0 ? somaConfianca / achados.length : 1;
  
  // Aplicar bonus de tipos críticos (máximo 30 pontos extras)
  bonusCritico = Math.min(bonusCritico, 30);
  
  // Calcular pontuação final (0-100)
  let pontuacaoFinal = pontuacaoBruta + bonusCritico;
  
  // Aplicar curva logarítmica para evitar saturação rápida
  // Isso permite que a pontuação cresça mais lentamente após certo ponto
  if (pontuacaoFinal > 50) {
    pontuacaoFinal = 50 + (Math.log10(pontuacaoFinal - 49) * 20);
  }
  
  // Garantir que está entre 0 e 100
  pontuacaoFinal = Math.min(100, Math.max(0, Math.round(pontuacaoFinal)));
  
  // Determinar classificação
  let classificacao: ScoreRisco['classificacao'];
  let cor: string;
  let descricao: string;
  let recomendacaoPrincipal: string;
  
  if (pontuacaoFinal >= 80) {
    classificacao = 'CRITICO';
    cor = '#dc2626'; // Vermelho
    descricao = 'Risco crítico identificado. Ação imediata necessária.';
    recomendacaoPrincipal = 'URGENTE: Acione o plano de resposta a incidentes e priorize a remediação dos achados críticos.';
  } else if (pontuacaoFinal >= 60) {
    classificacao = 'ALTO';
    cor = '#ea580c'; // Laranja escuro
    descricao = 'Risco alto detectado. Requer atenção prioritária.';
    recomendacaoPrincipal = 'Priorize a correção dos achados de alto risco nas próximas 48 horas.';
  } else if (pontuacaoFinal >= 40) {
    classificacao = 'MEDIO';
    cor = '#f59e0b'; // Amarelo/Laranja
    descricao = 'Risco moderado identificado. Planeje correções.';
    recomendacaoPrincipal = 'Elabore um plano de remediação para os achados identificados.';
  } else if (pontuacaoFinal >= 20) {
    classificacao = 'BAIXO';
    cor = '#84cc16'; // Verde claro
    descricao = 'Risco baixo. Algumas melhorias recomendadas.';
    recomendacaoPrincipal = 'Revise os achados e implemente melhorias conforme disponibilidade.';
  } else {
    classificacao = 'MINIMO';
    cor = '#22c55e'; // Verde
    descricao = 'Risco mínimo. Postura de segurança adequada.';
    recomendacaoPrincipal = 'Continue monitorando e mantenha as boas práticas de segurança.';
  }
  
  return {
    pontuacao: pontuacaoFinal,
    classificacao,
    cor,
    descricao,
    detalhes: {
      pontosPorSeveridade: {
        critico: contagem.critico * PESOS_RISCO[NivelRisco.CRITICO],
        alto: contagem.alto * PESOS_RISCO[NivelRisco.ALTO],
        medio: contagem.medio * PESOS_RISCO[NivelRisco.MEDIO],
        baixo: contagem.baixo * PESOS_RISCO[NivelRisco.BAIXO],
        informativo: contagem.informativo * PESOS_RISCO[NivelRisco.INFORMATIVO],
      },
      multiplicadorConfianca: Math.round(multiplicadorConfianca * 100) / 100,
      bonusNegativo: bonusCritico,
    },
    recomendacaoPrincipal,
  };
}

// Gerar resumo executivo baseado no score
export function gerarResumoExecutivo(
  score: ScoreRisco,
  achados: AchadoParaScore[],
  nomeEmpresa: string,
  dominio: string
): string {
  const totalAchados = achados.length;
  const criticos = achados.filter(a => a.nivelRisco === NivelRisco.CRITICO).length;
  const altos = achados.filter(a => a.nivelRisco === NivelRisco.ALTO).length;
  const medios = achados.filter(a => a.nivelRisco === NivelRisco.MEDIO).length;
  const baixos = achados.filter(a => a.nivelRisco === NivelRisco.BAIXO).length;
  
  let resumo = `## Resumo Executivo\n\n`;
  resumo += `A análise de segurança realizada para **${nomeEmpresa}** (${dominio}) identificou `;
  resumo += `**${totalAchados} achado(s)** de segurança, resultando em um score de risco de `;
  resumo += `**${score.pontuacao}/100** (${score.classificacao}).\n\n`;
  
  resumo += `### Distribuição por Severidade\n\n`;
  resumo += `| Severidade | Quantidade |\n`;
  resumo += `|------------|------------|\n`;
  resumo += `| Crítico | ${criticos} |\n`;
  resumo += `| Alto | ${altos} |\n`;
  resumo += `| Médio | ${medios} |\n`;
  resumo += `| Baixo | ${baixos} |\n\n`;
  
  resumo += `### Avaliação\n\n`;
  resumo += `${score.descricao}\n\n`;
  
  resumo += `### Recomendação Principal\n\n`;
  resumo += `${score.recomendacaoPrincipal}\n`;
  
  return resumo;
}

// Calcular tendência comparando com varredura anterior
export function calcularTendencia(
  scoreAtual: number,
  scoreAnterior: number | null
): { direcao: 'melhor' | 'pior' | 'estavel'; diferenca: number } {
  if (scoreAnterior === null) {
    return { direcao: 'estavel', diferenca: 0 };
  }
  
  const diferenca = scoreAtual - scoreAnterior;
  
  if (Math.abs(diferenca) < 5) {
    return { direcao: 'estavel', diferenca };
  }
  
  return {
    direcao: diferenca > 0 ? 'pior' : 'melhor',
    diferenca: Math.abs(diferenca),
  };
}
