/**
 * Advanced Scoring Service - Sistema de Scoring com 5 Eixos
 * 
 * Calcula score de risco 0-100 baseado em 5 dimensões:
 * - exposure: Quão público/acessível está o dado
 * - exploitability: Facilidade de exploração
 * - dataSensitivity: Sensibilidade dos dados
 * - scale: Quantidade de registros afetados
 * - confidence: Confiança na detecção
 */

import { VulnClass, getVulnClassDetails, classifyFinding } from './vulnClassService';

// Interface para os 5 eixos de scoring
export interface ScoringAxes {
  exposure: number;        // 0-1: Quão público/acessível
  exploitability: number;  // 0-1: Facilidade de exploração
  dataSensitivity: number; // 0-1: Sensibilidade dos dados
  scale: number;           // 0-1: Quantidade de registros
  confidence: number;      // 0-1: Confiança na detecção
}

// Pesos padrão para cada eixo
export const DEFAULT_WEIGHTS: ScoringAxes = {
  exposure: 0.25,
  exploitability: 0.25,
  dataSensitivity: 0.20,
  scale: 0.15,
  confidence: 0.15
};

// Níveis de risco baseados no score
export type RiskLevel = 'CRITICO' | 'ALTO' | 'MEDIO' | 'BAIXO';

export interface RiskLevelConfig {
  level: RiskLevel;
  minScore: number;
  maxScore: number;
  color: string;
  hexColor: string;
  label: string;
  description: string;
}

export const RISK_LEVELS: RiskLevelConfig[] = [
  {
    level: 'CRITICO',
    minScore: 75,
    maxScore: 100,
    color: 'red',
    hexColor: '#DC2626',
    label: 'Crítico',
    description: 'Risco iminente que requer ação imediata. Potencial de impacto severo nos negócios.'
  },
  {
    level: 'ALTO',
    minScore: 50,
    maxScore: 74,
    color: 'orange',
    hexColor: '#F97316',
    label: 'Alto',
    description: 'Risco significativo que deve ser tratado com urgência. Potencial de impacto considerável.'
  },
  {
    level: 'MEDIO',
    minScore: 25,
    maxScore: 49,
    color: 'yellow',
    hexColor: '#EAB308',
    label: 'Médio',
    description: 'Risco moderado que deve ser monitorado e tratado no curto prazo.'
  },
  {
    level: 'BAIXO',
    minScore: 0,
    maxScore: 24,
    color: 'green',
    hexColor: '#22C55E',
    label: 'Baixo',
    description: 'Risco baixo que pode ser tratado em ciclos normais de manutenção.'
  }
];

// Mapeamento de sensibilidade de dados
export const DATA_SENSITIVITY_MAP: Record<string, number> = {
  // Máxima sensibilidade (1.0)
  'senha': 1.0,
  'password': 1.0,
  'credencial': 1.0,
  'credential': 1.0,
  'token': 1.0,
  'api_key': 1.0,
  'private_key': 1.0,
  'secret': 1.0,
  'cpf': 1.0,
  'ssn': 1.0,
  'cartao_credito': 1.0,
  'credit_card': 1.0,
  
  // Alta sensibilidade (0.8)
  'dados_bancarios': 0.8,
  'bank_data': 0.8,
  'dados_saude': 0.8,
  'health_data': 0.8,
  'biometrico': 0.8,
  'biometric': 0.8,
  'rg': 0.8,
  'passaporte': 0.8,
  
  // Média sensibilidade (0.6)
  'email': 0.6,
  'telefone': 0.6,
  'phone': 0.6,
  'endereco': 0.6,
  'address': 0.6,
  'nome_completo': 0.6,
  'full_name': 0.6,
  
  // Baixa sensibilidade (0.4)
  'nome': 0.4,
  'name': 0.4,
  'empresa': 0.4,
  'company': 0.4,
  'cargo': 0.4,
  'job_title': 0.4,
  
  // Mínima sensibilidade (0.2)
  'dominio': 0.2,
  'domain': 0.2,
  'ip': 0.2,
  'url': 0.2,
  'certificado': 0.2,
  'certificate': 0.2
};

// Mapeamento de confiança por fonte
export const SOURCE_CONFIDENCE_MAP: Record<string, number> = {
  'hudson rock': 0.95,
  'have i been pwned': 0.95,
  'hibp': 0.95,
  'shodan': 0.90,
  'virustotal': 0.90,
  'cisa kev': 0.95,
  'ransomware.live': 0.85,
  'urlhaus': 0.85,
  'threatfox': 0.85,
  'leakix': 0.80,
  'crt.sh': 0.90,
  'crtsh': 0.90,
  'abuseipdb': 0.85,
  'alienvault otx': 0.80,
  'otx': 0.80,
  'urlscan': 0.80,
  'github': 0.75,
  'pastebin': 0.70,
  'psbdmp': 0.70,
  'intelligence x': 0.80,
  'default': 0.70
};

/**
 * Calcula o score de exposure baseado nas características do achado
 */
export function calculateExposure(finding: any): number {
  let exposure = 0.5; // Base

  const titulo = (finding.titulo || '').toLowerCase();
  const descricao = (finding.descricao || '').toLowerCase();
  const combinedText = `${titulo} ${descricao}`;

  // Aumenta exposure se dados estão publicamente acessíveis
  if (combinedText.includes('público') || combinedText.includes('public')) {
    exposure += 0.3;
  }
  if (combinedText.includes('exposto') || combinedText.includes('exposed')) {
    exposure += 0.25;
  }
  if (combinedText.includes('internet') || combinedText.includes('web')) {
    exposure += 0.15;
  }
  if (combinedText.includes('dark web') || combinedText.includes('darknet')) {
    exposure += 0.2;
  }
  if (combinedText.includes('vazamento') || combinedText.includes('leak')) {
    exposure += 0.2;
  }

  // Usa defaults da VulnClass se disponível
  const vulnClass = classifyFinding(finding);
  const classDetails = getVulnClassDetails(vulnClass);
  if (classDetails) {
    exposure = Math.max(exposure, classDetails.defaultExposure * 0.8);
  }

  return Math.min(1.0, Math.max(0, exposure));
}

/**
 * Calcula o score de exploitability baseado nas características do achado
 */
export function calculateExploitability(finding: any): number {
  let exploitability = 0.5; // Base

  const titulo = (finding.titulo || '').toLowerCase();
  const descricao = (finding.descricao || '').toLowerCase();
  const combinedText = `${titulo} ${descricao}`;

  // Aumenta exploitability se há exploits conhecidos
  if (combinedText.includes('exploit') || combinedText.includes('poc')) {
    exploitability += 0.3;
  }
  if (combinedText.includes('cve-')) {
    exploitability += 0.2;
  }
  if (combinedText.includes('kev') || combinedText.includes('actively exploited')) {
    exploitability += 0.35;
  }
  if (combinedText.includes('senha') || combinedText.includes('password')) {
    exploitability += 0.25;
  }
  if (combinedText.includes('texto plano') || combinedText.includes('plaintext')) {
    exploitability += 0.2;
  }
  if (combinedText.includes('infostealer')) {
    exploitability += 0.3;
  }

  // Usa defaults da VulnClass se disponível
  const vulnClass = classifyFinding(finding);
  const classDetails = getVulnClassDetails(vulnClass);
  if (classDetails) {
    exploitability = Math.max(exploitability, classDetails.defaultExploitability * 0.8);
  }

  return Math.min(1.0, Math.max(0, exploitability));
}

/**
 * Calcula o score de sensibilidade dos dados
 */
export function calculateDataSensitivity(finding: any): number {
  const titulo = (finding.titulo || '').toLowerCase();
  const descricao = (finding.descricao || '').toLowerCase();
  const combinedText = `${titulo} ${descricao}`;

  let maxSensitivity = 0.3; // Base

  // Verifica cada tipo de dado sensível
  for (const [dataType, sensitivity] of Object.entries(DATA_SENSITIVITY_MAP)) {
    if (combinedText.includes(dataType)) {
      maxSensitivity = Math.max(maxSensitivity, sensitivity);
    }
  }

  // Usa defaults da VulnClass se disponível
  const vulnClass = classifyFinding(finding);
  const classDetails = getVulnClassDetails(vulnClass);
  if (classDetails) {
    maxSensitivity = Math.max(maxSensitivity, classDetails.defaultDataSensitivity * 0.8);
  }

  return maxSensitivity;
}

/**
 * Calcula o score de scale baseado na quantidade de registros afetados
 */
export function calculateScale(finding: any): number {
  const evidencias = finding.evidencias || {};
  
  // Tenta extrair quantidade de registros de diferentes campos
  let recordCount = 0;
  
  if (evidencias.totalUsuarios) {
    recordCount = Math.max(recordCount, evidencias.totalUsuarios);
  }
  if (evidencias.totalFuncionarios) {
    recordCount = Math.max(recordCount, evidencias.totalFuncionarios);
  }
  if (evidencias.pwnCount) {
    recordCount = Math.max(recordCount, evidencias.pwnCount);
  }
  if (evidencias.affectedRecords) {
    recordCount = Math.max(recordCount, evidencias.affectedRecords);
  }
  if (evidencias.count) {
    recordCount = Math.max(recordCount, evidencias.count);
  }

  // Extrai números do título/descrição se não encontrou nas evidências
  if (recordCount === 0) {
    const titulo = finding.titulo || '';
    const match = titulo.match(/(\d+)\s*(credenciais?|usuários?|registros?|senhas?|emails?)/i);
    if (match) {
      recordCount = parseInt(match[1], 10);
    }
  }

  // Normaliza para escala 0-1 usando escala logarítmica
  if (recordCount === 0) return 0.1;
  if (recordCount < 10) return 0.2;
  if (recordCount < 100) return 0.4;
  if (recordCount < 1000) return 0.6;
  if (recordCount < 10000) return 0.8;
  if (recordCount < 100000) return 0.9;
  return 1.0;
}

/**
 * Calcula o score de confidence baseado na fonte
 */
export function calculateConfidence(finding: any): number {
  const fonte = (finding.fonte || '').toLowerCase();
  
  // Procura a fonte no mapa de confiança
  for (const [sourceName, confidence] of Object.entries(SOURCE_CONFIDENCE_MAP)) {
    if (fonte.includes(sourceName)) {
      return confidence;
    }
  }
  
  return SOURCE_CONFIDENCE_MAP['default'];
}

/**
 * Calcula os 5 eixos de scoring para um achado
 */
export function calculateAllAxes(finding: any): ScoringAxes {
  return {
    exposure: calculateExposure(finding),
    exploitability: calculateExploitability(finding),
    dataSensitivity: calculateDataSensitivity(finding),
    scale: calculateScale(finding),
    confidence: calculateConfidence(finding)
  };
}

/**
 * Calcula o score final (0-100) baseado nos 5 eixos e pesos
 */
export function calculateFinalScore(
  axes: ScoringAxes,
  weights: ScoringAxes = DEFAULT_WEIGHTS
): number {
  const weightedSum = 
    (axes.exposure * weights.exposure) +
    (axes.exploitability * weights.exploitability) +
    (axes.dataSensitivity * weights.dataSensitivity) +
    (axes.scale * weights.scale) +
    (axes.confidence * weights.confidence);
  
  // Normaliza para 0-100
  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);
  const normalizedScore = (weightedSum / totalWeight) * 100;
  
  return Math.round(Math.min(100, Math.max(0, normalizedScore)));
}

/**
 * Determina o nível de risco baseado no score
 */
export function getRiskLevel(score: number): RiskLevelConfig {
  for (const level of RISK_LEVELS) {
    if (score >= level.minScore && score <= level.maxScore) {
      return level;
    }
  }
  return RISK_LEVELS[RISK_LEVELS.length - 1]; // Default: BAIXO
}

/**
 * Calcula o score completo para um achado
 */
export function scoreFinding(finding: any, customWeights?: ScoringAxes): {
  score: number;
  axes: ScoringAxes;
  riskLevel: RiskLevelConfig;
  vulnClass: VulnClass;
} {
  const axes = calculateAllAxes(finding);
  const score = calculateFinalScore(axes, customWeights);
  const riskLevel = getRiskLevel(score);
  const vulnClass = classifyFinding(finding);
  
  return {
    score,
    axes,
    riskLevel,
    vulnClass
  };
}

/**
 * Calcula o score agregado para uma varredura completa
 */
export function calculateAggregateScore(findings: any[], customWeights?: ScoringAxes): {
  overallScore: number;
  riskLevel: RiskLevelConfig;
  findingScores: Array<{ finding: any; score: number; axes: ScoringAxes; riskLevel: RiskLevelConfig; vulnClass: VulnClass }>;
  breakdown: {
    byVulnClass: Record<VulnClass, { count: number; avgScore: number }>;
    byRiskLevel: Record<RiskLevel, number>;
    axesAverage: ScoringAxes;
  };
} {
  if (findings.length === 0) {
    return {
      overallScore: 0,
      riskLevel: RISK_LEVELS[RISK_LEVELS.length - 1],
      findingScores: [],
      breakdown: {
        byVulnClass: {} as Record<VulnClass, { count: number; avgScore: number }>,
        byRiskLevel: { CRITICO: 0, ALTO: 0, MEDIO: 0, BAIXO: 0 },
        axesAverage: { exposure: 0, exploitability: 0, dataSensitivity: 0, scale: 0, confidence: 0 }
      }
    };
  }

  // Calcula score para cada achado
  const findingScores = findings.map(finding => ({
    finding,
    ...scoreFinding(finding, customWeights)
  }));

  // Calcula score geral (média ponderada por severidade)
  const severityWeights: Record<string, number> = {
    'CRITICO': 4,
    'ALTO': 3,
    'MEDIO': 2,
    'BAIXO': 1
  };

  let totalWeight = 0;
  let weightedSum = 0;
  
  for (const fs of findingScores) {
    const weight = severityWeights[fs.riskLevel.level] || 1;
    weightedSum += fs.score * weight;
    totalWeight += weight;
  }

  const overallScore = Math.round(weightedSum / totalWeight);
  const riskLevel = getRiskLevel(overallScore);

  // Breakdown por VulnClass
  const byVulnClass: Record<VulnClass, { count: number; avgScore: number; totalScore: number }> = {} as any;
  for (const fs of findingScores) {
    if (!byVulnClass[fs.vulnClass]) {
      byVulnClass[fs.vulnClass] = { count: 0, avgScore: 0, totalScore: 0 };
    }
    byVulnClass[fs.vulnClass].count++;
    byVulnClass[fs.vulnClass].totalScore += fs.score;
  }
  for (const vc of Object.keys(byVulnClass) as VulnClass[]) {
    byVulnClass[vc].avgScore = Math.round(byVulnClass[vc].totalScore / byVulnClass[vc].count);
    delete (byVulnClass[vc] as any).totalScore;
  }

  // Breakdown por RiskLevel
  const byRiskLevel: Record<RiskLevel, number> = { CRITICO: 0, ALTO: 0, MEDIO: 0, BAIXO: 0 };
  for (const fs of findingScores) {
    byRiskLevel[fs.riskLevel.level]++;
  }

  // Média dos eixos
  const axesAverage: ScoringAxes = {
    exposure: 0,
    exploitability: 0,
    dataSensitivity: 0,
    scale: 0,
    confidence: 0
  };
  for (const fs of findingScores) {
    axesAverage.exposure += fs.axes.exposure;
    axesAverage.exploitability += fs.axes.exploitability;
    axesAverage.dataSensitivity += fs.axes.dataSensitivity;
    axesAverage.scale += fs.axes.scale;
    axesAverage.confidence += fs.axes.confidence;
  }
  const count = findingScores.length;
  axesAverage.exposure = Math.round((axesAverage.exposure / count) * 100) / 100;
  axesAverage.exploitability = Math.round((axesAverage.exploitability / count) * 100) / 100;
  axesAverage.dataSensitivity = Math.round((axesAverage.dataSensitivity / count) * 100) / 100;
  axesAverage.scale = Math.round((axesAverage.scale / count) * 100) / 100;
  axesAverage.confidence = Math.round((axesAverage.confidence / count) * 100) / 100;

  return {
    overallScore,
    riskLevel,
    findingScores,
    breakdown: {
      byVulnClass,
      byRiskLevel,
      axesAverage
    }
  };
}

// Interface para resultado do score (compatibilidade com pdfService)
export interface ScoreResult {
  scoreFinal: number;
  nivel: 'CRÍTICO' | 'ALTO' | 'MÉDIO' | 'BAIXO';
  eixos: ScoringAxes;
  fatores: string[];
}

// Função de compatibilidade para pdfService
export function calcularScoreAvancado(achado: any): ScoreResult {
  const result = scoreFinding(achado);
  return {
    scoreFinal: result.score,
    nivel: result.riskLevel.level === 'CRITICO' ? 'CRÍTICO' : 
           result.riskLevel.level === 'ALTO' ? 'ALTO' : 
           result.riskLevel.level === 'MEDIO' ? 'MÉDIO' : 'BAIXO',
    eixos: result.axes,
    fatores: [
      `Exposição: ${Math.round(result.axes.exposure * 100)}%`,
      `Explorabilidade: ${Math.round(result.axes.exploitability * 100)}%`,
      `Sensibilidade: ${Math.round(result.axes.dataSensitivity * 100)}%`,
      `Escala: ${Math.round(result.axes.scale * 100)}%`,
      `Confiança: ${Math.round(result.axes.confidence * 100)}%`
    ]
  };
}

export default {
  calculateAllAxes,
  calculateFinalScore,
  getRiskLevel,
  scoreFinding,
  calculateAggregateScore,
  calcularScoreAvancado,
  DEFAULT_WEIGHTS,
  RISK_LEVELS,
  DATA_SENSITIVITY_MAP,
  SOURCE_CONFIDENCE_MAP
};
