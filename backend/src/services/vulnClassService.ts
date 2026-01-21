/**
 * VulnClass Service - Sistema de Classificação de Vulnerabilidades
 * 
 * Define 8 classes prioritárias de vulnerabilidade para categorização
 * de achados de segurança no Sistema Sentinela TI.
 */

// Tipos de classes de vulnerabilidade
export type VulnClass = 
  | 'SECRETS_LEAK'           // Credenciais/tokens vazados
  | 'DATA_EXPOSURE_PUBLIC'   // Dados expostos publicamente
  | 'PHISHING_SOCIAL_ENG'    // Phishing e engenharia social
  | 'RANSOMWARE_IMPACT'      // Impacto de ransomware
  | 'UNPATCHED_EXPLOITED'    // CVEs não corrigidas/exploradas
  | 'MALWARE_C2'             // Malware e Command & Control
  | 'ACCOUNT_TAKEOVER'       // Contas comprometidas
  | 'THIRD_PARTY_RISK';      // Risco de terceiros

// Interface para detalhes de cada classe
export interface VulnClassDetails {
  class: VulnClass;
  name: string;
  description: string;
  severity: 'CRITICO' | 'ALTO' | 'MEDIO' | 'BAIXO';
  indicators: string[];
  sources: string[];
  defaultExposure: number;
  defaultExploitability: number;
  defaultDataSensitivity: number;
}

// Definição completa de cada classe de vulnerabilidade
export const VULN_CLASS_DEFINITIONS: Record<VulnClass, VulnClassDetails> = {
  SECRETS_LEAK: {
    class: 'SECRETS_LEAK',
    name: 'Vazamento de Credenciais',
    description: 'Credenciais, tokens de API, senhas ou chaves criptográficas expostas em vazamentos de dados, repositórios públicos ou logs de infostealers.',
    severity: 'CRITICO',
    indicators: [
      'Senhas em texto plano',
      'Tokens de API expostos',
      'Chaves SSH/PGP vazadas',
      'Credenciais em repositórios Git',
      'Logs de infostealers (VIDAR, RedLine, StealC)',
      'Dumps de banco de dados com hashes'
    ],
    sources: ['Have I Been Pwned', 'GitHub', 'LeakIX', 'VirusTotal'],
    defaultExposure: 0.95,
    defaultExploitability: 0.90,
    defaultDataSensitivity: 1.0
  },

  DATA_EXPOSURE_PUBLIC: {
    class: 'DATA_EXPOSURE_PUBLIC',
    name: 'Exposição de Dados Públicos',
    description: 'Dados sensíveis expostos publicamente na internet, incluindo bancos de dados abertos, buckets S3 mal configurados e APIs sem autenticação.',
    severity: 'CRITICO',
    indicators: [
      'Elasticsearch/MongoDB expostos',
      'Buckets S3/Azure Blob públicos',
      'APIs sem autenticação',
      'Backups expostos',
      'Diretórios listáveis',
      'Arquivos sensíveis indexados'
    ],
    sources: ['Shodan', 'LeakIX', 'crt.sh', 'URLScan'],
    defaultExposure: 1.0,
    defaultExploitability: 0.85,
    defaultDataSensitivity: 0.80
  },

  PHISHING_SOCIAL_ENG: {
    class: 'PHISHING_SOCIAL_ENG',
    name: 'Phishing e Engenharia Social',
    description: 'Domínios de phishing, páginas falsas ou campanhas de engenharia social direcionadas à organização.',
    severity: 'ALTO',
    indicators: [
      'Domínios typosquatting',
      'Páginas de login falsas',
      'Emails de phishing reportados',
      'Certificados SSL suspeitos',
      'Domínios recém-registrados similares'
    ],
    sources: ['crt.sh', 'URLScan', 'PhishTank', 'OpenPhish', 'VirusTotal'],
    defaultExposure: 0.70,
    defaultExploitability: 0.75,
    defaultDataSensitivity: 0.60
  },

  RANSOMWARE_IMPACT: {
    class: 'RANSOMWARE_IMPACT',
    name: 'Impacto de Ransomware',
    description: 'Organização listada como vítima de ransomware ou indicadores de comprometimento por grupos de ransomware.',
    severity: 'CRITICO',
    indicators: [
      'Listagem em site de leak de ransomware',
      'Dados publicados por grupo de ransomware',
      'Indicadores de criptografia maliciosa',
      'Comunicação com C2 de ransomware'
    ],
    sources: ['Ransomware.live', 'ThreatFox', 'AlienVault OTX'],
    defaultExposure: 1.0,
    defaultExploitability: 1.0,
    defaultDataSensitivity: 0.95
  },

  UNPATCHED_EXPLOITED: {
    class: 'UNPATCHED_EXPLOITED',
    name: 'CVEs Não Corrigidas',
    description: 'Vulnerabilidades conhecidas (CVEs) não corrigidas em sistemas expostos, especialmente aquelas ativamente exploradas.',
    severity: 'CRITICO',
    indicators: [
      'CVEs com CVSS >= 7.0',
      'CVEs no catálogo CISA KEV',
      'Exploits públicos disponíveis',
      'Serviços desatualizados expostos',
      'Versões vulneráveis detectadas'
    ],
    sources: ['Shodan', 'CISA KEV', 'VirusTotal', 'AbuseIPDB'],
    defaultExposure: 0.85,
    defaultExploitability: 0.95,
    defaultDataSensitivity: 0.70
  },

  MALWARE_C2: {
    class: 'MALWARE_C2',
    name: 'Malware e C2',
    description: 'Indicadores de comprometimento por malware, comunicação com servidores de comando e controle ou URLs maliciosas.',
    severity: 'CRITICO',
    indicators: [
      'URLs de distribuição de malware',
      'IPs de C2 conhecidos',
      'Hashes de malware associados',
      'Domínios de DGA detectados',
      'Tráfego para botnets'
    ],
    sources: ['URLhaus', 'ThreatFox', 'VirusTotal', 'AlienVault OTX', 'AbuseIPDB'],
    defaultExposure: 0.80,
    defaultExploitability: 0.90,
    defaultDataSensitivity: 0.75
  },

  ACCOUNT_TAKEOVER: {
    class: 'ACCOUNT_TAKEOVER',
    name: 'Contas Comprometidas',
    description: 'Contas de usuários comprometidas através de credential stuffing, vazamentos ou infostealers.',
    severity: 'ALTO',
    indicators: [
      'Emails em múltiplos breaches',
      'Senhas reutilizadas detectadas',
      'Sessões de infostealer',
      'Tentativas de login suspeitas',
      'Credenciais corporativas em dumps'
    ],
    sources: ['Have I Been Pwned', 'LeakIX', 'VirusTotal', 'AbuseIPDB'],
    defaultExposure: 0.75,
    defaultExploitability: 0.80,
    defaultDataSensitivity: 0.85
  },

  THIRD_PARTY_RISK: {
    class: 'THIRD_PARTY_RISK',
    name: 'Risco de Terceiros',
    description: 'Riscos originados de fornecedores, parceiros ou serviços de terceiros utilizados pela organização.',
    severity: 'MEDIO',
    indicators: [
      'Vazamentos em fornecedores',
      'Subdomínios de terceiros comprometidos',
      'APIs de parceiros expostas',
      'Certificados de terceiros expirados',
      'Dependências vulneráveis'
    ],
    sources: ['crt.sh', 'Shodan', 'GitHub', 'URLScan'],
    defaultExposure: 0.60,
    defaultExploitability: 0.55,
    defaultDataSensitivity: 0.50
  }
};

/**
 * Classifica um achado em uma VulnClass baseado em suas características
 */
export function classifyFinding(finding: {
  fonte: string;
  titulo: string;
  descricao?: string;
  nivelRisco: string;
  tipo?: string;
  evidencias?: any;
}): VulnClass {
  const titulo = finding.titulo.toLowerCase();
  const descricao = (finding.descricao || '').toLowerCase();
  const fonte = finding.fonte.toLowerCase();
  const tipo = (finding.tipo || '').toLowerCase();
  const combinedText = `${titulo} ${descricao} ${tipo}`;

  // Ransomware - prioridade máxima
  if (combinedText.includes('ransomware') || 
      combinedText.includes('leak site') ||
      fonte.includes('ransomware')) {
    return 'RANSOMWARE_IMPACT';
  }

  // Malware e C2
  if (combinedText.includes('malware') || 
      combinedText.includes('c2') ||
      combinedText.includes('command and control') ||
      combinedText.includes('botnet') ||
      combinedText.includes('trojan') ||
      fonte.includes('urlhaus') ||
      fonte.includes('threatfox')) {
    return 'MALWARE_C2';
  }

  // CVEs não corrigidas
  if (combinedText.includes('cve-') || 
      combinedText.includes('vulnerabilidade') ||
      combinedText.includes('vulnerability') ||
      combinedText.includes('exploit') ||
      combinedText.includes('kev') ||
      fonte.includes('cisa')) {
    return 'UNPATCHED_EXPLOITED';
  }

  // Vazamento de credenciais
  if (combinedText.includes('credencial') || 
      combinedText.includes('credential') ||
      combinedText.includes('senha') ||
      combinedText.includes('password') ||
      combinedText.includes('infostealer') ||
      combinedText.includes('token') ||
      combinedText.includes('api key') ||
      (fonte.includes('hudson') && combinedText.includes('comprometid'))) {
    return 'SECRETS_LEAK';
  }

  // Contas comprometidas
  if (combinedText.includes('breach') || 
      combinedText.includes('vazamento') ||
      combinedText.includes('pwned') ||
      combinedText.includes('conta comprometida') ||
      fonte.includes('hibp')) {
    return 'ACCOUNT_TAKEOVER';
  }

  // Phishing
  if (combinedText.includes('phishing') || 
      combinedText.includes('typosquat') ||
      combinedText.includes('fake') ||
      combinedText.includes('spoof') ||
      combinedText.includes('engenharia social')) {
    return 'PHISHING_SOCIAL_ENG';
  }

  // Exposição de dados
  if (combinedText.includes('exposto') || 
      combinedText.includes('exposed') ||
      combinedText.includes('público') ||
      combinedText.includes('public') ||
      combinedText.includes('open port') ||
      combinedText.includes('porta aberta') ||
      fonte.includes('shodan') ||
      fonte.includes('leakix')) {
    return 'DATA_EXPOSURE_PUBLIC';
  }

  // Risco de terceiros
  if (combinedText.includes('terceiro') || 
      combinedText.includes('third party') ||
      combinedText.includes('fornecedor') ||
      combinedText.includes('vendor') ||
      combinedText.includes('subdomínio') ||
      combinedText.includes('subdomain')) {
    return 'THIRD_PARTY_RISK';
  }

  // Default baseado na severidade
  if (finding.nivelRisco === 'CRITICO') {
    return 'SECRETS_LEAK';
  } else if (finding.nivelRisco === 'ALTO') {
    return 'ACCOUNT_TAKEOVER';
  } else if (finding.nivelRisco === 'MEDIO') {
    return 'DATA_EXPOSURE_PUBLIC';
  }

  return 'THIRD_PARTY_RISK';
}

/**
 * Retorna os detalhes de uma classe de vulnerabilidade
 */
export function getVulnClassDetails(vulnClass: VulnClass): VulnClassDetails {
  return VULN_CLASS_DEFINITIONS[vulnClass];
}

/**
 * Retorna todas as classes de vulnerabilidade ordenadas por severidade
 */
export function getAllVulnClasses(): VulnClassDetails[] {
  const severityOrder = { 'CRITICO': 0, 'ALTO': 1, 'MEDIO': 2, 'BAIXO': 3 };
  return Object.values(VULN_CLASS_DEFINITIONS).sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );
}

/**
 * Agrupa achados por VulnClass
 */
export function groupFindingsByVulnClass(findings: any[]): Map<VulnClass, any[]> {
  const grouped = new Map<VulnClass, any[]>();
  
  for (const finding of findings) {
    const vulnClass = classifyFinding(finding);
    if (!grouped.has(vulnClass)) {
      grouped.set(vulnClass, []);
    }
    grouped.get(vulnClass)!.push({
      ...finding,
      vulnClass,
      vulnClassDetails: getVulnClassDetails(vulnClass)
    });
  }
  
  return grouped;
}

// Alias para compatibilidade
export const classificarVulnerabilidade = classifyFinding;
export const VULN_CLASS_INFO = VULN_CLASS_DEFINITIONS;

export default {
  classifyFinding,
  classificarVulnerabilidade,
  getVulnClassDetails,
  getAllVulnClasses,
  groupFindingsByVulnClass,
  VULN_CLASS_DEFINITIONS,
  VULN_CLASS_INFO
};
