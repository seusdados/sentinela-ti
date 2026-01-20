// ============================================================================
// SENTINELA - Serviço de Conformidade LGPD
// Mapeia achados para artigos relevantes da LGPD
// ============================================================================

import { NivelRisco } from '@prisma/client';

export interface ArtigoLGPD {
  numero: string;
  titulo: string;
  resumo: string;
  texto: string;
  relevancia: 'ALTA' | 'MEDIA' | 'BAIXA';
}

export interface AvaliacaoLGPD {
  artigosRelevantes: ArtigoLGPD[];
  recomendacoesConformidade: string[];
  riscoLGPD: 'ALTO' | 'MEDIO' | 'BAIXO';
  pontuacaoConformidade: number; // 0-100
  acoesPrioritarias: string[];
}

// Base de artigos da LGPD relevantes para segurança
const ARTIGOS_LGPD: Record<string, ArtigoLGPD> = {
  'art6': {
    numero: 'Art. 6°',
    titulo: 'Princípios do Tratamento de Dados',
    resumo: 'Estabelece os princípios que devem nortear o tratamento de dados pessoais.',
    texto: 'As atividades de tratamento de dados pessoais deverão observar a boa-fé e os seguintes princípios: finalidade, adequação, necessidade, livre acesso, qualidade dos dados, transparência, segurança, prevenção, não discriminação e responsabilização.',
    relevancia: 'ALTA',
  },
  'art46': {
    numero: 'Art. 46',
    titulo: 'Segurança e Sigilo de Dados',
    resumo: 'Obriga a adoção de medidas de segurança para proteção dos dados pessoais.',
    texto: 'Os agentes de tratamento devem adotar medidas de segurança, técnicas e administrativas aptas a proteger os dados pessoais de acessos não autorizados e de situações acidentais ou ilícitas de destruição, perda, alteração, comunicação ou qualquer forma de tratamento inadequado ou ilícito.',
    relevancia: 'ALTA',
  },
  'art47': {
    numero: 'Art. 47',
    titulo: 'Sigilo Profissional',
    resumo: 'Estabelece o dever de sigilo sobre dados pessoais.',
    texto: 'Os agentes de tratamento ou qualquer outra pessoa que intervenha em uma das fases do tratamento obriga-se a garantir a segurança da informação prevista nesta Lei em relação aos dados pessoais, mesmo após o seu término.',
    relevancia: 'MEDIA',
  },
  'art48': {
    numero: 'Art. 48',
    titulo: 'Comunicação de Incidente de Segurança',
    resumo: 'Obriga a comunicação de incidentes de segurança à ANPD e aos titulares.',
    texto: 'O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência de incidente de segurança que possa acarretar risco ou dano relevante aos titulares. A comunicação deverá ser feita em prazo razoável e mencionar: a natureza dos dados afetados, os titulares envolvidos, as medidas técnicas e de segurança utilizadas, os riscos relacionados ao incidente, os motivos da demora (se houver) e as medidas adotadas para reverter ou mitigar os efeitos.',
    relevancia: 'ALTA',
  },
  'art49': {
    numero: 'Art. 49',
    titulo: 'Sistemas de Tratamento',
    resumo: 'Estabelece requisitos para sistemas que tratam dados pessoais.',
    texto: 'Os sistemas utilizados para o tratamento de dados pessoais devem ser estruturados de forma a atender aos requisitos de segurança, aos padrões de boas práticas e de governança e aos princípios gerais previstos nesta Lei e às demais normas regulamentares.',
    relevancia: 'ALTA',
  },
  'art50': {
    numero: 'Art. 50',
    titulo: 'Boas Práticas e Governança',
    resumo: 'Incentiva a adoção de regras de boas práticas e governança.',
    texto: 'Os controladores e operadores, no âmbito de suas competências, pelo tratamento de dados pessoais, individualmente ou por meio de associações, poderão formular regras de boas práticas e de governança que estabeleçam as condições de organização, o regime de funcionamento, os procedimentos, incluindo reclamações e petições de titulares, as normas de segurança, os padrões técnicos, as obrigações específicas para os diversos envolvidos no tratamento, as ações educativas, os mecanismos internos de supervisão e de mitigação de riscos e outros aspectos relacionados ao tratamento de dados pessoais.',
    relevancia: 'MEDIA',
  },
  'art52': {
    numero: 'Art. 52',
    titulo: 'Sanções Administrativas',
    resumo: 'Estabelece as sanções aplicáveis em caso de infrações.',
    texto: 'Os agentes de tratamento de dados, em razão das infrações cometidas às normas previstas nesta Lei, ficam sujeitos às seguintes sanções administrativas aplicáveis pela autoridade nacional: advertência, multa simples de até 2% do faturamento (limitada a R$ 50 milhões por infração), multa diária, publicização da infração, bloqueio e eliminação dos dados pessoais, suspensão parcial do funcionamento do banco de dados, suspensão do exercício da atividade de tratamento e proibição parcial ou total do exercício de atividades relacionadas a tratamento de dados.',
    relevancia: 'ALTA',
  },
  'art18': {
    numero: 'Art. 18',
    titulo: 'Direitos do Titular',
    resumo: 'Estabelece os direitos dos titulares de dados pessoais.',
    texto: 'O titular dos dados pessoais tem direito a obter do controlador, em relação aos dados do titular por ele tratados, a qualquer momento e mediante requisição: confirmação da existência de tratamento, acesso aos dados, correção de dados incompletos, inexatos ou desatualizados, anonimização, bloqueio ou eliminação de dados desnecessários, excessivos ou tratados em desconformidade com a Lei, portabilidade dos dados, eliminação dos dados pessoais tratados com o consentimento do titular, informação das entidades públicas e privadas com as quais o controlador realizou uso compartilhado de dados, informação sobre a possibilidade de não fornecer consentimento e sobre as consequências da negativa, e revogação do consentimento.',
    relevancia: 'MEDIA',
  },
};

// Mapeamento de tipos de achados para artigos LGPD
const MAPEAMENTO_ACHADOS_LGPD: Record<string, string[]> = {
  // Vazamentos de dados
  'vazamento_credenciais': ['art46', 'art48', 'art52'],
  'vazamento_dados': ['art46', 'art48', 'art52'],
  'infostealer_credentials': ['art46', 'art48', 'art52'],
  'infostealer_summary': ['art46', 'art48', 'art52'],
  'email_vazado': ['art46', 'art48', 'art18'],
  
  // Ransomware
  'ransomware_victim': ['art46', 'art48', 'art52'],
  
  // Vulnerabilidades
  'vulnerabilidade_conhecida': ['art46', 'art49'],
  'cve_critica': ['art46', 'art49', 'art52'],
  'cve_explorada': ['art46', 'art49'],
  'vulnerabilidades_detectadas': ['art46', 'art49'],
  
  // Infraestrutura exposta
  'banco_dados': ['art46', 'art49', 'art52'],
  'servico_alto_risco': ['art46', 'art49'],
  'servicos_alto_risco': ['art46', 'art49'],
  'infraestrutura_exposta': ['art46', 'art49'],
  
  // Malware e ameaças
  'malware_ioc': ['art46', 'art48'],
  'url_maliciosa': ['art46'],
  'malware_url': ['art46'],
  
  // Subdomínios sensíveis
  'painel_administrativo': ['art46', 'art49'],
  'ambiente_desenvolvimento': ['art46', 'art50'],
  'sistema_pagamento': ['art46', 'art49', 'art52'],
  'autenticacao': ['art46', 'art49'],
  
  // Secrets e código
  'secret_exposto': ['art46', 'art47'],
  'credencial_codigo': ['art46', 'art47'],
  
  // Geral
  'default': ['art6', 'art46'],
};

export interface AchadoParaLGPD {
  tipo: string;
  nivelRisco: NivelRisco;
  titulo: string;
  descricao?: string;
}

export function avaliarConformidadeLGPD(achados: AchadoParaLGPD[]): AvaliacaoLGPD {
  const artigosEncontrados = new Set<string>();
  const recomendacoes: string[] = [];
  const acoesPrioritarias: string[] = [];
  
  // Contadores de risco
  let pontosCriticos = 0;
  let pontosAltos = 0;
  let pontosMedios = 0;
  
  // Analisar cada achado
  achados.forEach(achado => {
    const artigos = MAPEAMENTO_ACHADOS_LGPD[achado.tipo] || MAPEAMENTO_ACHADOS_LGPD['default'];
    artigos.forEach(art => artigosEncontrados.add(art));
    
    // Contabilizar pontos de risco
    switch (achado.nivelRisco) {
      case NivelRisco.CRITICO:
        pontosCriticos += 3;
        break;
      case NivelRisco.ALTO:
        pontosAltos += 2;
        break;
      case NivelRisco.MEDIO:
        pontosMedios += 1;
        break;
    }
    
    // Gerar recomendações específicas
    if (achado.tipo.includes('vazamento') || achado.tipo.includes('infostealer')) {
      if (!recomendacoes.includes('Notificar ANPD sobre incidente de segurança (Art. 48)')) {
        recomendacoes.push('Notificar ANPD sobre incidente de segurança (Art. 48)');
        acoesPrioritarias.push('Preparar comunicação de incidente para ANPD em até 72 horas');
      }
      if (!recomendacoes.includes('Notificar titulares afetados sobre o vazamento')) {
        recomendacoes.push('Notificar titulares afetados sobre o vazamento');
      }
    }
    
    if (achado.tipo.includes('ransomware')) {
      acoesPrioritarias.push('URGENTE: Ativar plano de resposta a incidentes');
      acoesPrioritarias.push('Comunicar ANPD imediatamente sobre ataque de ransomware');
      recomendacoes.push('Documentar todo o incidente para eventual fiscalização');
    }
    
    if (achado.tipo.includes('banco_dados') || achado.tipo.includes('vulnerabilidade')) {
      recomendacoes.push('Revisar medidas técnicas de segurança (Art. 46)');
      recomendacoes.push('Atualizar sistemas e aplicar patches de segurança (Art. 49)');
    }
  });
  
  // Adicionar recomendações gerais se houver achados
  if (achados.length > 0) {
    recomendacoes.push('Revisar e atualizar política de segurança da informação');
    recomendacoes.push('Documentar medidas de segurança adotadas para demonstrar conformidade');
    recomendacoes.push('Treinar colaboradores sobre proteção de dados pessoais');
  }
  
  // Calcular pontuação de conformidade (inverso do risco)
  const pontuacaoRisco = Math.min(100, pontosCriticos * 15 + pontosAltos * 8 + pontosMedios * 3);
  const pontuacaoConformidade = Math.max(0, 100 - pontuacaoRisco);
  
  // Determinar nível de risco LGPD
  let riscoLGPD: 'ALTO' | 'MEDIO' | 'BAIXO';
  if (pontosCriticos > 0 || pontuacaoConformidade < 40) {
    riscoLGPD = 'ALTO';
  } else if (pontosAltos > 2 || pontuacaoConformidade < 70) {
    riscoLGPD = 'MEDIO';
  } else {
    riscoLGPD = 'BAIXO';
  }
  
  // Montar lista de artigos relevantes
  const artigosRelevantes = Array.from(artigosEncontrados)
    .map(art => ARTIGOS_LGPD[art])
    .filter(Boolean)
    .sort((a, b) => {
      const ordem = { 'ALTA': 0, 'MEDIA': 1, 'BAIXA': 2 };
      return ordem[a.relevancia] - ordem[b.relevancia];
    });
  
  return {
    artigosRelevantes,
    recomendacoesConformidade: [...new Set(recomendacoes)],
    riscoLGPD,
    pontuacaoConformidade,
    acoesPrioritarias: [...new Set(acoesPrioritarias)],
  };
}

// Gerar seção LGPD para o relatório PDF
export function gerarSecaoLGPD(avaliacao: AvaliacaoLGPD): string {
  let secao = `## Conformidade LGPD\n\n`;
  
  secao += `### Avaliação de Risco LGPD\n\n`;
  secao += `**Nível de Risco:** ${avaliacao.riscoLGPD}\n\n`;
  secao += `**Pontuação de Conformidade:** ${avaliacao.pontuacaoConformidade}/100\n\n`;
  
  if (avaliacao.acoesPrioritarias.length > 0) {
    secao += `### Ações Prioritárias\n\n`;
    avaliacao.acoesPrioritarias.forEach((acao, i) => {
      secao += `${i + 1}. ${acao}\n`;
    });
    secao += `\n`;
  }
  
  secao += `### Artigos Relevantes da LGPD\n\n`;
  avaliacao.artigosRelevantes.forEach(artigo => {
    secao += `#### ${artigo.numero} - ${artigo.titulo}\n\n`;
    secao += `> ${artigo.resumo}\n\n`;
    secao += `${artigo.texto}\n\n`;
  });
  
  secao += `### Recomendações de Conformidade\n\n`;
  avaliacao.recomendacoesConformidade.forEach((rec, i) => {
    secao += `${i + 1}. ${rec}\n`;
  });
  
  return secao;
}
