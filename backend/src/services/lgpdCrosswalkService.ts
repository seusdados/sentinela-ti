/**
 * LGPD Crosswalk Service - Mapeamento LGPD e ANPD Res 15/2024
 * 
 * Mapeia VulnClasses para artigos da LGPD, critérios da ANPD Resolução 15/2024,
 * e determina obrigatoriedade de comunicação à ANPD.
 */

import { VulnClass, getVulnClassDetails } from './vulnClassService';

// Artigos relevantes da LGPD (Lei nº 13.709/2018)
export interface LGPDArticle {
  number: string;
  title: string;
  summary: string;
  fullText: string;
  relevance: 'ALTA' | 'MEDIA' | 'BAIXA';
}

export const LGPD_ARTICLES: Record<string, LGPDArticle> = {
  'ART_6': {
    number: 'Art. 6º',
    title: 'Princípios do Tratamento de Dados',
    summary: 'Estabelece os princípios que devem nortear o tratamento de dados pessoais.',
    fullText: 'As atividades de tratamento de dados pessoais deverão observar a boa-fé e os seguintes princípios: finalidade, adequação, necessidade, livre acesso, qualidade dos dados, transparência, segurança, prevenção, não discriminação, responsabilização e prestação de contas.',
    relevance: 'MEDIA'
  },
  'ART_7': {
    number: 'Art. 7º',
    title: 'Bases Legais para Tratamento',
    summary: 'Define as hipóteses em que o tratamento de dados pessoais pode ser realizado.',
    fullText: 'O tratamento de dados pessoais somente poderá ser realizado nas seguintes hipóteses: consentimento, cumprimento de obrigação legal, execução de políticas públicas, estudos por órgão de pesquisa, execução de contrato, exercício de direitos em processo, proteção da vida, tutela da saúde, legítimo interesse, proteção do crédito.',
    relevance: 'MEDIA'
  },
  'ART_18': {
    number: 'Art. 18',
    title: 'Direitos do Titular',
    summary: 'Estabelece os direitos dos titulares de dados pessoais.',
    fullText: 'O titular dos dados pessoais tem direito a obter do controlador, em relação aos dados do titular por ele tratados, a qualquer momento e mediante requisição: confirmação da existência de tratamento, acesso aos dados, correção de dados incompletos, anonimização, bloqueio ou eliminação, portabilidade, eliminação dos dados tratados com consentimento, informação sobre compartilhamento, informação sobre a possibilidade de não fornecer consentimento, revogação do consentimento.',
    relevance: 'ALTA'
  },
  'ART_42': {
    number: 'Art. 42',
    title: 'Responsabilidade e Ressarcimento de Danos',
    summary: 'Estabelece a responsabilidade do controlador ou operador por danos causados.',
    fullText: 'O controlador ou o operador que, em razão do exercício de atividade de tratamento de dados pessoais, causar a outrem dano patrimonial, moral, individual ou coletivo, em violação à legislação de proteção de dados pessoais, é obrigado a repará-lo.',
    relevance: 'ALTA'
  },
  'ART_46': {
    number: 'Art. 46',
    title: 'Medidas de Segurança',
    summary: 'Obriga a adoção de medidas de segurança para proteção dos dados pessoais.',
    fullText: 'Os agentes de tratamento devem adotar medidas de segurança, técnicas e administrativas aptas a proteger os dados pessoais de acessos não autorizados e de situações acidentais ou ilícitas de destruição, perda, alteração, comunicação ou qualquer forma de tratamento inadequado ou ilícito.',
    relevance: 'ALTA'
  },
  'ART_47': {
    number: 'Art. 47',
    title: 'Sigilo dos Dados',
    summary: 'Estabelece o dever de sigilo sobre os dados pessoais.',
    fullText: 'Os agentes de tratamento ou qualquer outra pessoa que intervenha em uma das fases do tratamento obriga-se a garantir a segurança da informação prevista nesta Lei em relação aos dados pessoais, mesmo após o seu término.',
    relevance: 'ALTA'
  },
  'ART_48': {
    number: 'Art. 48',
    title: 'Comunicação de Incidente de Segurança',
    summary: 'Obriga a comunicação de incidentes de segurança à ANPD e aos titulares.',
    fullText: 'O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência de incidente de segurança que possa acarretar risco ou dano relevante aos titulares. A comunicação será feita em prazo razoável, conforme definido pela autoridade nacional, e deverá mencionar: a descrição da natureza dos dados pessoais afetados, as informações sobre os titulares envolvidos, a indicação das medidas técnicas e de segurança utilizadas, os riscos relacionados ao incidente, os motivos da demora (se houver), e as medidas que foram ou serão adotadas.',
    relevance: 'ALTA'
  },
  'ART_49': {
    number: 'Art. 49',
    title: 'Sistemas de Segurança',
    summary: 'Estabelece requisitos para sistemas de tratamento de dados.',
    fullText: 'Os sistemas utilizados para o tratamento de dados pessoais devem ser estruturados de forma a atender aos requisitos de segurança, aos padrões de boas práticas e de governança e aos princípios gerais previstos nesta Lei e às demais normas regulamentares.',
    relevance: 'MEDIA'
  },
  'ART_50': {
    number: 'Art. 50',
    title: 'Boas Práticas e Governança',
    summary: 'Incentiva a adoção de regras de boas práticas e governança.',
    fullText: 'Os controladores e operadores, no âmbito de suas competências, pelo tratamento de dados pessoais, individualmente ou por meio de associações, poderão formular regras de boas práticas e de governança que estabeleçam as condições de organização, o regime de funcionamento, os procedimentos, incluindo reclamações e petições de titulares, as normas de segurança, os padrões técnicos, as obrigações específicas para os diversos envolvidos no tratamento, as ações educativas, os mecanismos internos de supervisão e de mitigação de riscos e outros aspectos relacionados ao tratamento de dados pessoais.',
    relevance: 'MEDIA'
  },
  'ART_52': {
    number: 'Art. 52',
    title: 'Sanções Administrativas',
    summary: 'Estabelece as sanções aplicáveis em caso de infrações.',
    fullText: 'Os agentes de tratamento de dados, em razão das infrações cometidas às normas previstas nesta Lei, ficam sujeitos às seguintes sanções administrativas aplicáveis pela autoridade nacional: advertência, multa simples (até 2% do faturamento, limitado a R$ 50 milhões), multa diária, publicização da infração, bloqueio dos dados pessoais, eliminação dos dados pessoais, suspensão parcial do funcionamento do banco de dados, suspensão do exercício da atividade de tratamento, proibição parcial ou total do exercício de atividades relacionadas a tratamento de dados.',
    relevance: 'ALTA'
  }
};

// Critérios da ANPD Resolução 15/2024
export interface ANPDCriteria {
  id: string;
  name: string;
  description: string;
  requiresNotification: boolean;
  notificationDeadline: string;
  examples: string[];
}

export const ANPD_RES_15_2024_CRITERIA: Record<string, ANPDCriteria> = {
  'AUTENTICACAO': {
    id: 'AUTENTICACAO',
    name: 'Dados de Autenticação',
    description: 'Incidente envolvendo dados utilizados para autenticação em sistemas (senhas, tokens, credenciais).',
    requiresNotification: true,
    notificationDeadline: '3 dias úteis',
    examples: [
      'Vazamento de senhas',
      'Exposição de tokens de API',
      'Comprometimento de credenciais de acesso',
      'Logs de infostealers com credenciais'
    ]
  },
  'FINANCEIRO': {
    id: 'FINANCEIRO',
    name: 'Dados Financeiros',
    description: 'Incidente envolvendo dados financeiros ou que possam causar dano financeiro aos titulares.',
    requiresNotification: true,
    notificationDeadline: '3 dias úteis',
    examples: [
      'Vazamento de dados de cartão de crédito',
      'Exposição de dados bancários',
      'Comprometimento de informações de pagamento',
      'Acesso não autorizado a sistemas financeiros'
    ]
  },
  'LARGA_ESCALA': {
    id: 'LARGA_ESCALA',
    name: 'Tratamento em Larga Escala',
    description: 'Incidente que afeta um grande número de titulares de dados.',
    requiresNotification: true,
    notificationDeadline: '3 dias úteis',
    examples: [
      'Vazamento afetando mais de 100.000 titulares',
      'Exposição de base de dados de clientes',
      'Comprometimento de sistema com milhares de usuários'
    ]
  },
  'DADOS_SENSIVEIS': {
    id: 'DADOS_SENSIVEIS',
    name: 'Dados Sensíveis',
    description: 'Incidente envolvendo dados pessoais sensíveis conforme Art. 5º, II da LGPD.',
    requiresNotification: true,
    notificationDeadline: '3 dias úteis',
    examples: [
      'Vazamento de dados de saúde',
      'Exposição de dados biométricos',
      'Comprometimento de informações sobre origem racial/étnica',
      'Vazamento de dados sobre convicções religiosas ou políticas'
    ]
  },
  'MENORES': {
    id: 'MENORES',
    name: 'Dados de Crianças e Adolescentes',
    description: 'Incidente envolvendo dados de crianças e adolescentes.',
    requiresNotification: true,
    notificationDeadline: '3 dias úteis',
    examples: [
      'Vazamento de dados de alunos menores de idade',
      'Exposição de informações de crianças em plataformas',
      'Comprometimento de dados de menores em sistemas educacionais'
    ]
  },
  'RISCO_RELEVANTE': {
    id: 'RISCO_RELEVANTE',
    name: 'Risco ou Dano Relevante',
    description: 'Incidente que pode acarretar risco ou dano relevante aos titulares.',
    requiresNotification: true,
    notificationDeadline: '3 dias úteis',
    examples: [
      'Possibilidade de fraude de identidade',
      'Risco de discriminação',
      'Potencial para danos à reputação',
      'Risco de prejuízo financeiro significativo'
    ]
  }
};

// Interface para mapeamento VulnClass -> LGPD/ANPD
export interface LGPDCrosswalk {
  vulnClass: VulnClass;
  applicableArticles: LGPDArticle[];
  anpdCriteria: ANPDCriteria[];
  requiresANPDNotification: boolean;
  notificationDeadline: string;
  recommendations: string[];
  immediateActions: string[];
  shortTermActions: string[];
  mediumTermActions: string[];
}

// Mapeamento completo VulnClass -> LGPD/ANPD
export const VULN_CLASS_LGPD_MAPPING: Record<VulnClass, LGPDCrosswalk> = {
  SECRETS_LEAK: {
    vulnClass: 'SECRETS_LEAK',
    applicableArticles: [
      LGPD_ARTICLES['ART_46'],
      LGPD_ARTICLES['ART_47'],
      LGPD_ARTICLES['ART_48'],
      LGPD_ARTICLES['ART_52']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['AUTENTICACAO'],
      ANPD_RES_15_2024_CRITERIA['RISCO_RELEVANTE']
    ],
    requiresANPDNotification: true,
    notificationDeadline: '3 dias úteis',
    recommendations: [
      'Revogar imediatamente todas as credenciais comprometidas',
      'Forçar reset de senha para todos os usuários afetados',
      'Implementar autenticação multifator (MFA)',
      'Revisar políticas de complexidade de senha',
      'Monitorar tentativas de acesso não autorizado',
      'Notificar titulares afetados sobre o incidente'
    ],
    immediateActions: [
      'Revogar credenciais comprometidas',
      'Bloquear acessos suspeitos',
      'Ativar monitoramento intensivo',
      'Iniciar processo de comunicação à ANPD'
    ],
    shortTermActions: [
      'Forçar troca de senhas',
      'Implementar MFA',
      'Revisar logs de acesso',
      'Comunicar titulares afetados'
    ],
    mediumTermActions: [
      'Implementar gestão de credenciais privilegiadas',
      'Adotar cofre de senhas corporativo',
      'Treinar colaboradores sobre segurança de credenciais',
      'Revisar política de segurança da informação'
    ]
  },

  DATA_EXPOSURE_PUBLIC: {
    vulnClass: 'DATA_EXPOSURE_PUBLIC',
    applicableArticles: [
      LGPD_ARTICLES['ART_6'],
      LGPD_ARTICLES['ART_46'],
      LGPD_ARTICLES['ART_48'],
      LGPD_ARTICLES['ART_49']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['LARGA_ESCALA'],
      ANPD_RES_15_2024_CRITERIA['RISCO_RELEVANTE']
    ],
    requiresANPDNotification: true,
    notificationDeadline: '3 dias úteis',
    recommendations: [
      'Remover imediatamente os dados expostos do acesso público',
      'Identificar a extensão da exposição',
      'Avaliar quais dados foram potencialmente acessados',
      'Implementar controles de acesso adequados',
      'Revisar configurações de segurança de todos os sistemas',
      'Realizar varredura de segurança em toda a infraestrutura'
    ],
    immediateActions: [
      'Bloquear acesso público aos dados',
      'Documentar a exposição',
      'Preservar evidências',
      'Iniciar comunicação à ANPD'
    ],
    shortTermActions: [
      'Avaliar dados acessados',
      'Implementar controles de acesso',
      'Revisar configurações de segurança',
      'Notificar titulares se necessário'
    ],
    mediumTermActions: [
      'Implementar DLP (Data Loss Prevention)',
      'Adotar classificação de dados',
      'Realizar pentest periódico',
      'Treinar equipe sobre configuração segura'
    ]
  },

  PHISHING_SOCIAL_ENG: {
    vulnClass: 'PHISHING_SOCIAL_ENG',
    applicableArticles: [
      LGPD_ARTICLES['ART_46'],
      LGPD_ARTICLES['ART_50']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['AUTENTICACAO']
    ],
    requiresANPDNotification: false,
    notificationDeadline: 'Avaliar caso a caso',
    recommendations: [
      'Reportar domínios de phishing para takedown',
      'Alertar colaboradores sobre a campanha de phishing',
      'Monitorar credenciais potencialmente comprometidas',
      'Implementar filtros de email anti-phishing',
      'Realizar treinamento de conscientização',
      'Monitorar domínios similares (typosquatting)'
    ],
    immediateActions: [
      'Solicitar takedown do domínio malicioso',
      'Alertar colaboradores',
      'Bloquear domínio no firewall/proxy',
      'Verificar se houve comprometimento'
    ],
    shortTermActions: [
      'Implementar DMARC/DKIM/SPF',
      'Treinar colaboradores',
      'Revisar filtros de email',
      'Monitorar domínios similares'
    ],
    mediumTermActions: [
      'Implementar simulações de phishing',
      'Adotar solução anti-phishing avançada',
      'Registrar domínios defensivos',
      'Estabelecer processo de resposta a phishing'
    ]
  },

  RANSOMWARE_IMPACT: {
    vulnClass: 'RANSOMWARE_IMPACT',
    applicableArticles: [
      LGPD_ARTICLES['ART_46'],
      LGPD_ARTICLES['ART_48'],
      LGPD_ARTICLES['ART_52']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['LARGA_ESCALA'],
      ANPD_RES_15_2024_CRITERIA['RISCO_RELEVANTE'],
      ANPD_RES_15_2024_CRITERIA['DADOS_SENSIVEIS']
    ],
    requiresANPDNotification: true,
    notificationDeadline: '3 dias úteis (URGENTE)',
    recommendations: [
      'Isolar sistemas afetados imediatamente',
      'Não pagar o resgate',
      'Acionar equipe de resposta a incidentes',
      'Comunicar à ANPD e autoridades competentes',
      'Avaliar extensão do comprometimento',
      'Restaurar sistemas a partir de backups seguros',
      'Investigar vetor de entrada do ransomware'
    ],
    immediateActions: [
      'Isolar sistemas afetados',
      'Acionar resposta a incidentes',
      'Preservar evidências',
      'Comunicar à ANPD (URGENTE)'
    ],
    shortTermActions: [
      'Restaurar de backups',
      'Investigar vetor de entrada',
      'Comunicar titulares afetados',
      'Reportar às autoridades'
    ],
    mediumTermActions: [
      'Implementar EDR/XDR',
      'Revisar política de backup',
      'Segmentar rede',
      'Treinar equipe sobre ransomware'
    ]
  },

  UNPATCHED_EXPLOITED: {
    vulnClass: 'UNPATCHED_EXPLOITED',
    applicableArticles: [
      LGPD_ARTICLES['ART_46'],
      LGPD_ARTICLES['ART_49']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['RISCO_RELEVANTE']
    ],
    requiresANPDNotification: false,
    notificationDeadline: 'Avaliar se houve comprometimento de dados',
    recommendations: [
      'Aplicar patches de segurança imediatamente',
      'Isolar sistemas vulneráveis até correção',
      'Verificar se houve exploração da vulnerabilidade',
      'Implementar processo de gestão de vulnerabilidades',
      'Priorizar CVEs no catálogo CISA KEV',
      'Monitorar tentativas de exploração'
    ],
    immediateActions: [
      'Aplicar patches críticos',
      'Isolar sistemas vulneráveis',
      'Verificar logs de exploração',
      'Implementar mitigações temporárias'
    ],
    shortTermActions: [
      'Completar patching',
      'Realizar varredura de vulnerabilidades',
      'Revisar configurações de segurança',
      'Atualizar inventário de ativos'
    ],
    mediumTermActions: [
      'Implementar gestão de vulnerabilidades',
      'Adotar processo de patching regular',
      'Implementar WAF/IPS',
      'Realizar pentests periódicos'
    ]
  },

  MALWARE_C2: {
    vulnClass: 'MALWARE_C2',
    applicableArticles: [
      LGPD_ARTICLES['ART_46'],
      LGPD_ARTICLES['ART_48']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['AUTENTICACAO'],
      ANPD_RES_15_2024_CRITERIA['RISCO_RELEVANTE']
    ],
    requiresANPDNotification: true,
    notificationDeadline: '3 dias úteis',
    recommendations: [
      'Isolar sistemas comprometidos',
      'Bloquear comunicação com C2 no firewall',
      'Realizar análise forense',
      'Identificar extensão do comprometimento',
      'Limpar sistemas infectados',
      'Revisar credenciais que podem ter sido exfiltradas'
    ],
    immediateActions: [
      'Isolar sistemas infectados',
      'Bloquear IPs/domínios de C2',
      'Preservar evidências',
      'Iniciar análise forense'
    ],
    shortTermActions: [
      'Limpar sistemas',
      'Revogar credenciais expostas',
      'Comunicar à ANPD se dados foram afetados',
      'Investigar vetor de infecção'
    ],
    mediumTermActions: [
      'Implementar EDR',
      'Adotar threat intelligence',
      'Treinar usuários',
      'Revisar controles de endpoint'
    ]
  },

  ACCOUNT_TAKEOVER: {
    vulnClass: 'ACCOUNT_TAKEOVER',
    applicableArticles: [
      LGPD_ARTICLES['ART_18'],
      LGPD_ARTICLES['ART_46'],
      LGPD_ARTICLES['ART_48']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['AUTENTICACAO'],
      ANPD_RES_15_2024_CRITERIA['RISCO_RELEVANTE']
    ],
    requiresANPDNotification: true,
    notificationDeadline: '3 dias úteis',
    recommendations: [
      'Forçar logout de todas as sessões',
      'Resetar credenciais comprometidas',
      'Implementar MFA',
      'Notificar titulares afetados',
      'Revisar atividades suspeitas nas contas',
      'Implementar detecção de credential stuffing'
    ],
    immediateActions: [
      'Forçar logout',
      'Resetar senhas',
      'Bloquear IPs suspeitos',
      'Notificar titulares'
    ],
    shortTermActions: [
      'Implementar MFA',
      'Revisar logs de acesso',
      'Comunicar à ANPD',
      'Verificar dados acessados'
    ],
    mediumTermActions: [
      'Implementar detecção de anomalias',
      'Adotar CAPTCHA/rate limiting',
      'Monitorar credenciais em vazamentos',
      'Treinar usuários sobre senhas seguras'
    ]
  },

  THIRD_PARTY_RISK: {
    vulnClass: 'THIRD_PARTY_RISK',
    applicableArticles: [
      LGPD_ARTICLES['ART_42'],
      LGPD_ARTICLES['ART_46']
    ],
    anpdCriteria: [
      ANPD_RES_15_2024_CRITERIA['RISCO_RELEVANTE']
    ],
    requiresANPDNotification: false,
    notificationDeadline: 'Avaliar impacto nos dados da organização',
    recommendations: [
      'Avaliar impacto do incidente no terceiro',
      'Verificar quais dados foram compartilhados',
      'Revisar contratos e SLAs de segurança',
      'Solicitar relatório de incidente do fornecedor',
      'Avaliar necessidade de comunicação à ANPD',
      'Revisar processo de due diligence de fornecedores'
    ],
    immediateActions: [
      'Contatar fornecedor',
      'Avaliar dados compartilhados',
      'Documentar incidente',
      'Revisar acessos do terceiro'
    ],
    shortTermActions: [
      'Obter relatório do fornecedor',
      'Avaliar impacto nos titulares',
      'Revisar contratos',
      'Comunicar à ANPD se necessário'
    ],
    mediumTermActions: [
      'Implementar gestão de terceiros',
      'Revisar due diligence',
      'Adotar questionários de segurança',
      'Monitorar postura de segurança de fornecedores'
    ]
  }
};

/**
 * Obtém o mapeamento LGPD/ANPD para uma VulnClass
 */
export function getLGPDCrosswalk(vulnClass: VulnClass): LGPDCrosswalk {
  return VULN_CLASS_LGPD_MAPPING[vulnClass];
}

/**
 * Verifica se um achado requer comunicação à ANPD
 */
export function requiresANPDNotification(vulnClass: VulnClass): boolean {
  return VULN_CLASS_LGPD_MAPPING[vulnClass].requiresANPDNotification;
}

/**
 * Obtém o prazo de comunicação à ANPD
 */
export function getNotificationDeadline(vulnClass: VulnClass): string {
  return VULN_CLASS_LGPD_MAPPING[vulnClass].notificationDeadline;
}

/**
 * Obtém todas as recomendações para uma VulnClass
 */
export function getRecommendations(vulnClass: VulnClass): {
  immediate: string[];
  shortTerm: string[];
  mediumTerm: string[];
  all: string[];
} {
  const mapping = VULN_CLASS_LGPD_MAPPING[vulnClass];
  return {
    immediate: mapping.immediateActions,
    shortTerm: mapping.shortTermActions,
    mediumTerm: mapping.mediumTermActions,
    all: mapping.recommendations
  };
}

/**
 * Gera relatório de conformidade LGPD para uma lista de achados
 */
export function generateLGPDComplianceReport(findings: Array<{ vulnClass: VulnClass; titulo: string; nivelRisco: string }>): {
  requiresNotification: boolean;
  urgentDeadline: string | null;
  applicableArticles: LGPDArticle[];
  anpdCriteria: ANPDCriteria[];
  actionPlan: {
    immediate: string[];
    shortTerm: string[];
    mediumTerm: string[];
  };
  findingsAnalysis: Array<{
    finding: any;
    crosswalk: LGPDCrosswalk;
  }>;
} {
  const allArticles = new Map<string, LGPDArticle>();
  const allCriteria = new Map<string, ANPDCriteria>();
  const immediateActions = new Set<string>();
  const shortTermActions = new Set<string>();
  const mediumTermActions = new Set<string>();
  
  let requiresNotification = false;
  let urgentDeadline: string | null = null;
  
  const findingsAnalysis = findings.map(finding => {
    const crosswalk = getLGPDCrosswalk(finding.vulnClass);
    
    // Agregar artigos
    crosswalk.applicableArticles.forEach(art => {
      allArticles.set(art.number, art);
    });
    
    // Agregar critérios ANPD
    crosswalk.anpdCriteria.forEach(crit => {
      allCriteria.set(crit.id, crit);
    });
    
    // Agregar ações
    crosswalk.immediateActions.forEach(a => immediateActions.add(a));
    crosswalk.shortTermActions.forEach(a => shortTermActions.add(a));
    crosswalk.mediumTermActions.forEach(a => mediumTermActions.add(a));
    
    // Verificar notificação
    if (crosswalk.requiresANPDNotification) {
      requiresNotification = true;
      if (!urgentDeadline || crosswalk.notificationDeadline.includes('URGENTE')) {
        urgentDeadline = crosswalk.notificationDeadline;
      }
    }
    
    return { finding, crosswalk };
  });
  
  return {
    requiresNotification,
    urgentDeadline,
    applicableArticles: Array.from(allArticles.values()),
    anpdCriteria: Array.from(allCriteria.values()),
    actionPlan: {
      immediate: Array.from(immediateActions),
      shortTerm: Array.from(shortTermActions),
      mediumTerm: Array.from(mediumTermActions)
    },
    findingsAnalysis
  };
}

// Interface para resultado da análise LGPD (compatibilidade com pdfService)
export interface LGPDAnalysisResult {
  requerComunicacaoANPD: boolean;
  prazoComunicacao: string;
  criteriosANPD: string[];
  artigosAplicaveis: Array<{
    artigo: string;
    descricao: string;
    achadosRelacionados: number;
  }>;
  recomendacoes: string[];
}

// Função de compatibilidade para pdfService
export function analisarConformidadeLGPD(achados: any[]): LGPDAnalysisResult {
  const report = generateLGPDComplianceReport(achados);
  
  return {
    requerComunicacaoANPD: report.requiresNotification,
    prazoComunicacao: report.urgentDeadline || '3 dias úteis (Art. 48 LGPD)',
    criteriosANPD: report.anpdCriteria.map(c => c.name),
    artigosAplicaveis: report.applicableArticles.map(a => ({
      artigo: a.number,
      descricao: a.summary,
      achadosRelacionados: report.findingsAnalysis.filter(
        f => f.crosswalk.applicableArticles.some(art => art.number === a.number)
      ).length
    })),
    recomendacoes: [
      ...report.actionPlan.immediate.slice(0, 3),
      ...report.actionPlan.shortTerm.slice(0, 2),
      ...report.actionPlan.mediumTerm.slice(0, 2)
    ]
  };
}

export default {
  getLGPDCrosswalk,
  requiresANPDNotification,
  getNotificationDeadline,
  getRecommendations,
  generateLGPDComplianceReport,
  analisarConformidadeLGPD,
  LGPD_ARTICLES,
  ANPD_RES_15_2024_CRITERIA,
  VULN_CLASS_LGPD_MAPPING
};
