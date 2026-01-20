// ============================================================================
// SENTINELA - Serviço de Geração de Relatórios PDF
// Gera relatórios profissionais com capa, resumo executivo, achados, LGPD e glossário
// ============================================================================

import PDFDocument from 'pdfkit';
import { prisma } from '../config/prisma';
import { NivelRisco, FonteInformacao } from '@prisma/client';
import { classificarVulnerabilidade, VulnClass, VULN_CLASS_INFO } from './vulnClassService';
import { calcularScoreAvancado, ScoreResult } from './advancedScoringService';
import { analisarConformidadeLGPD, LGPDAnalysisResult } from './lgpdCrosswalkService';

// ============================================================================
// TIPOS E INTERFACES
// ============================================================================

interface DadosRelatorio {
  varredura: {
    id: string;
    criadoEm: Date;
    iniciadaEm?: Date | null;
    concluidaEm?: Date | null;
    escopo: string;
    totalAchados: number;
    achadosCriticos: number;
    achadosAltos: number;
    achadosMedios: number;
    achadosBaixos: number;
  };
  empresa: {
    nome: string;
    nomeFantasia?: string | null;
    cnpj?: string | null;
    setor?: string | null;
    dominios: string[];
    dpo?: {
      nome?: string | null;
      email?: string | null;
    } | null;
  };
  achados: {
    id: string;
    titulo: string;
    descricao?: string | null;
    recomendacao?: string | null;
    nivelRisco: NivelRisco;
    fonte: FonteInformacao;
    tipoEntidade: string;
    entidade: string;
    evidencia?: Record<string, unknown> | null;
    primeiraVezEm: Date;
    ultimaVezEm: Date;
    vulnClass?: VulnClass;
    scoreDetalhado?: ScoreResult;
  }[];
  execucoesFonte: {
    fonte: FonteInformacao;
    status: string;
    itensEncontrados: number;
    duracaoMs: number;
    usouCache: boolean;
    mensagemErro?: string | null;
  }[];
  scoreRisco: number;
  classificacaoRisco: string;
  scoreDetalhado?: ScoreResult;
  analiseLGPD?: LGPDAnalysisResult;
}

// ============================================================================
// CONSTANTES DE ESTILO
// ============================================================================

const CORES = {
  primaria: '#0f172a',
  secundaria: '#1e293b',
  destaque: '#10b981',
  critico: '#dc2626',
  alto: '#f97316',
  medio: '#eab308',
  baixo: '#3b82f6',
  informativo: '#6b7280',
  texto: '#1f2937',
  textoClaro: '#6b7280',
  fundo: '#f8fafc',
  branco: '#ffffff',
  verde: '#22c55e',
};

const FONTES = {
  titulo: 'Helvetica-Bold',
  subtitulo: 'Helvetica-Bold',
  corpo: 'Helvetica',
  negrito: 'Helvetica-Bold',
};

// ============================================================================
// GLOSSÁRIO DE TERMOS TÉCNICOS
// ============================================================================

const GLOSSARIO: Record<string, string> = {
  'Infostealer': 'Malware especializado em roubar credenciais, cookies e dados sensíveis do computador infectado.',
  'CVE': 'Common Vulnerabilities and Exposures - identificador único para vulnerabilidades de segurança conhecidas.',
  'CVSS': 'Common Vulnerability Scoring System - sistema de pontuação que avalia a gravidade de vulnerabilidades.',
  'Phishing': 'Técnica de engenharia social que usa comunicações fraudulentas para roubar informações.',
  'Ransomware': 'Malware que criptografa arquivos e exige pagamento para restaurar o acesso.',
  'C2/C&C': 'Command and Control - servidor usado por atacantes para controlar sistemas comprometidos.',
  'Breach': 'Vazamento de dados - exposição não autorizada de informações confidenciais.',
  'MFA/2FA': 'Autenticação multifator - método de segurança que requer múltiplas formas de verificação.',
  'EDR': 'Endpoint Detection and Response - solução de segurança para detectar e responder a ameaças.',
  'XDR': 'Extended Detection and Response - evolução do EDR com visibilidade ampliada.',
  'SIEM': 'Security Information and Event Management - sistema de gerenciamento de eventos de segurança.',
  'IoC': 'Indicator of Compromise - evidência de que um sistema foi comprometido.',
  'APT': 'Advanced Persistent Threat - ataque sofisticado e prolongado por grupos especializados.',
  'Zero-day': 'Vulnerabilidade desconhecida pelo fabricante, sem correção disponível.',
  'Botnet': 'Rede de computadores infectados controlados remotamente por atacantes.',
  'DDoS': 'Distributed Denial of Service - ataque que sobrecarrega sistemas com tráfego malicioso.',
  'SSL/TLS': 'Protocolos de criptografia para comunicação segura na internet.',
  'VPN': 'Virtual Private Network - rede privada virtual para conexões seguras.',
  'LGPD': 'Lei Geral de Proteção de Dados - legislação brasileira sobre proteção de dados pessoais.',
  'ANPD': 'Autoridade Nacional de Proteção de Dados - órgão responsável por fiscalizar a LGPD.',
  'DPO': 'Data Protection Officer - encarregado de proteção de dados na organização.',
  'Threat Intelligence': 'Inteligência de ameaças - informações sobre ameaças cibernéticas.',
  'Dark Web': 'Parte da internet acessível apenas por software especial, frequentemente usada para atividades ilícitas.',
  'Credential Stuffing': 'Ataque que usa credenciais vazadas para tentar acessar outras contas.',
  'Brute Force': 'Ataque que tenta adivinhar senhas testando todas as combinações possíveis.',
  'SQL Injection': 'Técnica de ataque que insere código malicioso em consultas de banco de dados.',
  'XSS': 'Cross-Site Scripting - vulnerabilidade que permite injetar scripts em páginas web.',
  'OSINT': 'Open Source Intelligence - inteligência obtida de fontes públicas.',
};

// ============================================================================
// FUNÇÕES AUXILIARES
// ============================================================================

function formatarData(data: Date | null | undefined): string {
  if (!data) return 'N/A';
  return new Intl.DateTimeFormat('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(data));
}

function formatarDataCurta(data: Date | null | undefined): string {
  if (!data) return 'N/A';
  return new Intl.DateTimeFormat('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  }).format(new Date(data));
}

function obterCorRisco(nivel: NivelRisco): string {
  switch (nivel) {
    case NivelRisco.CRITICO: return CORES.critico;
    case NivelRisco.ALTO: return CORES.alto;
    case NivelRisco.MEDIO: return CORES.medio;
    case NivelRisco.BAIXO: return CORES.baixo;
    default: return CORES.informativo;
  }
}

function obterLabelRisco(nivel: NivelRisco): string {
  switch (nivel) {
    case NivelRisco.CRITICO: return 'CRÍTICO';
    case NivelRisco.ALTO: return 'ALTO';
    case NivelRisco.MEDIO: return 'MÉDIO';
    case NivelRisco.BAIXO: return 'BAIXO';
    default: return 'INFORMATIVO';
  }
}

function obterCorScore(score: number): string {
  if (score >= 75) return CORES.critico;
  if (score >= 50) return CORES.alto;
  if (score >= 25) return CORES.medio;
  return CORES.verde;
}

function obterClassificacaoScore(score: number): string {
  if (score >= 75) return 'CRÍTICO';
  if (score >= 50) return 'ALTO';
  if (score >= 25) return 'MÉDIO';
  return 'BAIXO';
}

// Extrair termos técnicos do texto para o glossário
function extrairTermosGlossario(texto: string): string[] {
  const termosEncontrados: string[] = [];
  const textoLower = texto.toLowerCase();
  
  for (const termo of Object.keys(GLOSSARIO)) {
    if (textoLower.includes(termo.toLowerCase())) {
      termosEncontrados.push(termo);
    }
  }
  
  return [...new Set(termosEncontrados)];
}

// ============================================================================
// DESENHO DO SCORE VISUAL (CÍRCULO COLORIDO)
// ============================================================================

function desenharScoreCircular(
  doc: PDFKit.PDFDocument, 
  centerX: number, 
  centerY: number, 
  score: number, 
  raio: number = 50
) {
  const cor = obterCorScore(score);
  const classificacao = obterClassificacaoScore(score);
  
  // Círculo de fundo (cinza claro)
  doc.circle(centerX, centerY, raio)
     .lineWidth(10)
     .strokeColor('#e5e7eb')
     .stroke();
  
  // Arco do score (colorido)
  const angulo = (score / 100) * 360;
  const startAngle = -90; // Começar do topo
  const endAngle = startAngle + angulo;
  
  // Desenhar arco usando path
  if (score > 0) {
    const startRad = (startAngle * Math.PI) / 180;
    const endRad = (endAngle * Math.PI) / 180;
    
    // Calcular pontos do arco
    const startX = centerX + raio * Math.cos(startRad);
    const startY = centerY + raio * Math.sin(startRad);
    
    doc.save();
    doc.lineWidth(10);
    doc.strokeColor(cor);
    
    // Desenhar arco
    doc.path(`
      M ${startX} ${startY}
      A ${raio} ${raio} 0 ${angulo > 180 ? 1 : 0} 1 
        ${centerX + raio * Math.cos(endRad)} 
        ${centerY + raio * Math.sin(endRad)}
    `).stroke();
    
    doc.restore();
  }
  
  // Texto do score no centro
  doc.fillColor(cor)
     .font(FONTES.titulo)
     .fontSize(raio * 0.6)
     .text(score.toString(), centerX - raio * 0.4, centerY - raio * 0.25, { 
       width: raio * 0.8, 
       align: 'center' 
     });
  
  // Classificação abaixo
  doc.fillColor(CORES.texto)
     .font(FONTES.negrito)
     .fontSize(raio * 0.2)
     .text(classificacao, centerX - raio, centerY + raio + 10, { 
       width: raio * 2, 
       align: 'center' 
     });
}

// ============================================================================
// GERAÇÃO DAS SEÇÕES DO PDF
// ============================================================================

async function gerarCapa(doc: PDFKit.PDFDocument, dados: DadosRelatorio) {
  const pageWidth = doc.page.width;
  const pageHeight = doc.page.height;
  
  // Fundo gradiente (simulado com retângulos)
  doc.rect(0, 0, pageWidth, pageHeight).fill(CORES.primaria);
  doc.rect(0, pageHeight * 0.6, pageWidth, pageHeight * 0.4).fill(CORES.secundaria);
  
  // Logo/Ícone (escudo estilizado)
  const centerX = pageWidth / 2;
  doc.save();
  doc.translate(centerX - 40, 120);
  doc.path('M40 0 L80 20 L80 50 C80 80 40 100 40 100 C40 100 0 80 0 50 L0 20 Z')
     .fill(CORES.destaque);
  doc.path('M40 15 L65 30 L65 48 C65 68 40 82 40 82 C40 82 15 68 15 48 L15 30 Z')
     .fill(CORES.primaria);
  doc.restore();
  
  // Título
  doc.fillColor(CORES.branco)
     .font(FONTES.titulo)
     .fontSize(42)
     .text('SENTINELA TI', 0, 250, { align: 'center' });
  
  doc.fontSize(16)
     .font(FONTES.corpo)
     .text('Relatório de Inteligência de Ameaças', 0, 300, { align: 'center' });
  
  // Nome da empresa
  doc.fontSize(28)
     .font(FONTES.titulo)
     .text(dados.empresa.nome, 0, 360, { align: 'center' });
  
  if (dados.empresa.cnpj) {
    doc.fontSize(12)
       .font(FONTES.corpo)
       .fillColor(CORES.textoClaro)
       .text(`CNPJ: ${dados.empresa.cnpj}`, 0, 400, { align: 'center' });
  }
  
  // Score de Risco Visual (círculo colorido)
  const scoreY = 480;
  
  doc.fillColor(CORES.branco)
     .font(FONTES.subtitulo)
     .fontSize(14)
     .text('SCORE DE RISCO', 0, scoreY - 30, { align: 'center' });
  
  // Desenhar círculo do score
  const scoreColor = obterCorScore(dados.scoreRisco);
  
  // Círculo externo (fundo)
  doc.circle(centerX, scoreY + 50, 55)
     .lineWidth(12)
     .strokeColor('#374151')
     .stroke();
  
  // Círculo do score (colorido)
  doc.circle(centerX, scoreY + 50, 55)
     .lineWidth(12)
     .strokeColor(scoreColor)
     .stroke();
  
  // Valor do score
  doc.fillColor(scoreColor)
     .font(FONTES.titulo)
     .fontSize(40)
     .text(dados.scoreRisco.toString(), centerX - 30, scoreY + 30, { width: 60, align: 'center' });
  
  // Classificação
  doc.fillColor(CORES.branco)
     .font(FONTES.negrito)
     .fontSize(18)
     .text(dados.classificacaoRisco, 0, scoreY + 120, { align: 'center' });
  
  // Métricas rápidas
  const metricsY = scoreY + 170;
  const metricsWidth = 80;
  const metricsStart = centerX - (metricsWidth * 2);
  
  const metricas = [
    { label: 'Críticos', valor: dados.varredura.achadosCriticos, cor: CORES.critico },
    { label: 'Altos', valor: dados.varredura.achadosAltos, cor: CORES.alto },
    { label: 'Médios', valor: dados.varredura.achadosMedios, cor: CORES.medio },
    { label: 'Baixos', valor: dados.varredura.achadosBaixos, cor: CORES.baixo },
  ];
  
  metricas.forEach((m, i) => {
    const x = metricsStart + (i * metricsWidth);
    doc.fillColor(m.cor)
       .font(FONTES.titulo)
       .fontSize(24)
       .text(m.valor.toString(), x, metricsY, { width: metricsWidth, align: 'center' });
    doc.fillColor(CORES.textoClaro)
       .font(FONTES.corpo)
       .fontSize(10)
       .text(m.label, x, metricsY + 25, { width: metricsWidth, align: 'center' });
  });
  
  // Data do relatório
  doc.fillColor(CORES.textoClaro)
     .font(FONTES.corpo)
     .fontSize(11)
     .text(`Gerado em: ${formatarData(new Date())}`, 0, pageHeight - 80, { align: 'center' });
  
  doc.text(`Período da varredura: ${formatarDataCurta(dados.varredura.criadoEm)}`, 0, pageHeight - 60, { align: 'center' });
}

function gerarResumoExecutivo(doc: PDFKit.PDFDocument, dados: DadosRelatorio) {
  doc.addPage();
  
  const marginLeft = 50;
  const marginRight = 50;
  const contentWidth = doc.page.width - marginLeft - marginRight;
  let y = 50;
  
  // Cabeçalho
  doc.fillColor(CORES.primaria)
     .font(FONTES.titulo)
     .fontSize(24)
     .text('Resumo Executivo', marginLeft, y);
  
  y += 40;
  
  doc.moveTo(marginLeft, y).lineTo(doc.page.width - marginRight, y).strokeColor(CORES.destaque).lineWidth(2).stroke();
  y += 25;
  
  // Texto introdutório
  doc.fillColor(CORES.texto)
     .font(FONTES.corpo)
     .fontSize(11)
     .text(`Este relatório apresenta os resultados da varredura de inteligência de ameaças realizada para ${dados.empresa.nome}. A análise identificou ${dados.varredura.totalAchados} achados de segurança que requerem atenção.`, marginLeft, y, { width: contentWidth, align: 'justify' });
  
  y += 50;
  
  // Cards de métricas
  const cardWidth = (contentWidth - 30) / 4;
  const cardHeight = 80;
  
  const cards = [
    { label: 'Achados Críticos', valor: dados.varredura.achadosCriticos, cor: CORES.critico },
    { label: 'Achados Altos', valor: dados.varredura.achadosAltos, cor: CORES.alto },
    { label: 'Achados Médios', valor: dados.varredura.achadosMedios, cor: CORES.medio },
    { label: 'Achados Baixos', valor: dados.varredura.achadosBaixos, cor: CORES.baixo },
  ];
  
  cards.forEach((card, i) => {
    const x = marginLeft + (i * (cardWidth + 10));
    
    doc.roundedRect(x, y, cardWidth, cardHeight, 5).fill(CORES.fundo);
    doc.rect(x, y, 4, cardHeight).fill(card.cor);
    
    doc.fillColor(card.cor)
       .font(FONTES.titulo)
       .fontSize(28)
       .text(card.valor.toString(), x + 15, y + 15, { width: cardWidth - 20 });
    
    doc.fillColor(CORES.textoClaro)
       .font(FONTES.corpo)
       .fontSize(10)
       .text(card.label, x + 15, y + 50, { width: cardWidth - 20 });
  });
  
  y += cardHeight + 30;
  
  // Score detalhado (5 eixos)
  if (dados.scoreDetalhado) {
    doc.fillColor(CORES.primaria)
       .font(FONTES.subtitulo)
       .fontSize(14)
       .text('Análise de Risco por Eixo', marginLeft, y);
    
    y += 25;
    
    const eixos = [
      { label: 'Exposição', valor: dados.scoreDetalhado.eixos.exposure, desc: 'Quão público/acessível' },
      { label: 'Explorabilidade', valor: dados.scoreDetalhado.eixos.exploitability, desc: 'Facilidade de exploração' },
      { label: 'Sensibilidade', valor: dados.scoreDetalhado.eixos.dataSensitivity, desc: 'Criticidade dos dados' },
      { label: 'Escala', valor: dados.scoreDetalhado.eixos.scale, desc: 'Quantidade afetada' },
      { label: 'Confiança', valor: dados.scoreDetalhado.eixos.confidence, desc: 'Certeza da detecção' },
    ];
    
    eixos.forEach((eixo, i) => {
      const barWidth = contentWidth - 150;
      const barX = marginLeft + 100;
      const barY = y + (i * 30);
      
      // Label
      doc.fillColor(CORES.texto)
         .font(FONTES.corpo)
         .fontSize(10)
         .text(eixo.label, marginLeft, barY + 5, { width: 90 });
      
      // Barra de fundo
      doc.roundedRect(barX, barY, barWidth, 15, 3).fill('#e5e7eb');
      
      // Barra de valor
      const valorWidth = (eixo.valor / 1) * barWidth;
      const corBarra = eixo.valor >= 0.7 ? CORES.critico : 
                       eixo.valor >= 0.5 ? CORES.alto : 
                       eixo.valor >= 0.3 ? CORES.medio : CORES.verde;
      doc.roundedRect(barX, barY, valorWidth, 15, 3).fill(corBarra);
      
      // Valor
      doc.fillColor(CORES.texto)
         .font(FONTES.negrito)
         .fontSize(9)
         .text(`${Math.round(eixo.valor * 100)}%`, barX + barWidth + 10, barY + 3);
    });
    
    y += 170;
  }
  
  // Fontes consultadas
  doc.fillColor(CORES.primaria)
     .font(FONTES.subtitulo)
     .fontSize(14)
     .text('Fontes de Inteligência Consultadas', marginLeft, y);
  
  y += 25;
  
  const fontesOk = dados.execucoesFonte.filter(f => f.status === 'SUCESSO' || f.status === 'CONCLUIDO').length;
  const fontesTotal = dados.execucoesFonte.length;
  
  doc.fillColor(CORES.texto)
     .font(FONTES.corpo)
     .fontSize(10)
     .text(`${fontesOk} de ${fontesTotal} fontes consultadas com sucesso`, marginLeft, y);
  
  y += 20;
  
  // Lista de fontes
  dados.execucoesFonte.forEach((fonte, i) => {
    if (y > doc.page.height - 100) {
      doc.addPage();
      y = 50;
    }
    
    const statusOk = fonte.status === 'SUCESSO' || fonte.status === 'CONCLUIDO';
    const statusIcon = statusOk ? '✓' : '✗';
    const statusCor = statusOk ? CORES.destaque : CORES.critico;
    
    doc.fillColor(statusCor)
       .font(FONTES.negrito)
       .fontSize(10)
       .text(statusIcon, marginLeft, y, { continued: true });
    
    doc.fillColor(CORES.texto)
       .font(FONTES.corpo)
       .text(` ${fonte.fonte} - ${fonte.itensEncontrados} itens encontrados`, { continued: false });
    
    y += 18;
  });
}

function gerarSecaoAchados(doc: PDFKit.PDFDocument, dados: DadosRelatorio) {
  doc.addPage();
  
  const marginLeft = 50;
  const marginRight = 50;
  const contentWidth = doc.page.width - marginLeft - marginRight;
  let y = 50;
  
  // Cabeçalho
  doc.fillColor(CORES.primaria)
     .font(FONTES.titulo)
     .fontSize(24)
     .text('Achados de Segurança', marginLeft, y);
  
  y += 40;
  
  doc.moveTo(marginLeft, y).lineTo(doc.page.width - marginRight, y).strokeColor(CORES.destaque).lineWidth(2).stroke();
  y += 20;
  
  // Agrupar por severidade
  const ordemRisco: Record<NivelRisco, number> = {
    [NivelRisco.CRITICO]: 0,
    [NivelRisco.ALTO]: 1,
    [NivelRisco.MEDIO]: 2,
    [NivelRisco.BAIXO]: 3,
    [NivelRisco.INFORMATIVO]: 4,
  };
  
  const achadosOrdenados = [...dados.achados].sort((a, b) => 
    ordemRisco[a.nivelRisco] - ordemRisco[b.nivelRisco]
  );
  
  const grupos: Record<NivelRisco, typeof dados.achados> = {
    [NivelRisco.CRITICO]: [],
    [NivelRisco.ALTO]: [],
    [NivelRisco.MEDIO]: [],
    [NivelRisco.BAIXO]: [],
    [NivelRisco.INFORMATIVO]: [],
  };
  
  achadosOrdenados.forEach(a => grupos[a.nivelRisco].push(a));
  
  // Renderizar cada grupo
  Object.entries(grupos).forEach(([nivel, achados]) => {
    if (achados.length === 0) return;
    
    if (y > doc.page.height - 150) {
      doc.addPage();
      y = 50;
    }
    
    const cor = obterCorRisco(nivel as NivelRisco);
    const label = obterLabelRisco(nivel as NivelRisco);
    
    // Cabeçalho do grupo
    doc.roundedRect(marginLeft, y, contentWidth, 30, 3).fill(cor);
    doc.fillColor(CORES.branco)
       .font(FONTES.negrito)
       .fontSize(12)
       .text(`${label} (${achados.length})`, marginLeft + 15, y + 8);
    
    y += 40;
    
    // Achados do grupo
    achados.forEach((achado, index) => {
      if (y > doc.page.height - 180) {
        doc.addPage();
        y = 50;
      }
      
      const cardY = y;
      const cardHeight = 140;
      
      // Card do achado
      doc.roundedRect(marginLeft, cardY, contentWidth, cardHeight, 5).fill(CORES.fundo);
      doc.rect(marginLeft, cardY, 4, cardHeight).fill(cor);
      
      // Título
      doc.fillColor(CORES.primaria)
         .font(FONTES.negrito)
         .fontSize(11)
         .text(achado.titulo, marginLeft + 15, cardY + 10, { width: contentWidth - 30 });
      
      // Fonte e entidade
      doc.fillColor(CORES.textoClaro)
         .font(FONTES.corpo)
         .fontSize(9)
         .text(`Fonte: ${achado.fonte} | Entidade: ${achado.entidade}`, marginLeft + 15, cardY + 30);
      
      // VulnClass se disponível
      if (achado.vulnClass) {
        const vulnInfo = VULN_CLASS_INFO[achado.vulnClass];
        doc.fillColor(CORES.destaque)
           .font(FONTES.negrito)
           .fontSize(8)
           .text(`Classe: ${vulnInfo?.name || achado.vulnClass}`, marginLeft + 15, cardY + 45);
      }
      
      // Descrição
      if (achado.descricao) {
        doc.fillColor(CORES.texto)
           .font(FONTES.corpo)
           .fontSize(9)
           .text(achado.descricao.substring(0, 250) + (achado.descricao.length > 250 ? '...' : ''), marginLeft + 15, cardY + 60, { width: contentWidth - 30 });
      }
      
      // Recomendação
      if (achado.recomendacao) {
        doc.fillColor(CORES.destaque)
           .font(FONTES.negrito)
           .fontSize(8)
           .text('Recomendação:', marginLeft + 15, cardY + 105, { continued: true });
        doc.font(FONTES.corpo)
           .fillColor(CORES.texto)
           .text(` ${achado.recomendacao.substring(0, 150)}${achado.recomendacao.length > 150 ? '...' : ''}`);
      }
      
      y += cardHeight + 10;
    });
    
    y += 10;
  });
}

function gerarSecaoLGPD(doc: PDFKit.PDFDocument, dados: DadosRelatorio) {
  doc.addPage();
  
  const marginLeft = 50;
  const marginRight = 50;
  const contentWidth = doc.page.width - marginLeft - marginRight;
  let y = 50;
  
  // Cabeçalho
  doc.fillColor(CORES.primaria)
     .font(FONTES.titulo)
     .fontSize(24)
     .text('Conformidade LGPD', marginLeft, y);
  
  y += 40;
  
  doc.moveTo(marginLeft, y).lineTo(doc.page.width - marginRight, y).strokeColor(CORES.destaque).lineWidth(2).stroke();
  y += 20;
  
  // Introdução
  doc.fillColor(CORES.texto)
     .font(FONTES.corpo)
     .fontSize(11)
     .text('A Lei Geral de Proteção de Dados (Lei nº 13.709/2018) e a Resolução CD/ANPD nº 15/2024 estabelecem regras sobre proteção de dados pessoais e comunicação de incidentes. Os achados identificados nesta varredura podem ter implicações diretas na conformidade.', marginLeft, y, { width: contentWidth, align: 'justify' });
  
  y += 60;
  
  // Análise LGPD detalhada
  if (dados.analiseLGPD) {
    // Alerta de comunicação obrigatória
    if (dados.analiseLGPD.requerComunicacaoANPD) {
      doc.roundedRect(marginLeft, y, contentWidth, 60, 5).fill(CORES.critico);
      doc.fillColor(CORES.branco)
         .font(FONTES.negrito)
         .fontSize(12)
         .text('⚠ COMUNICAÇÃO À ANPD OBRIGATÓRIA', marginLeft + 15, y + 10);
      doc.font(FONTES.corpo)
         .fontSize(10)
         .text(`Prazo: ${dados.analiseLGPD.prazoComunicacao}. Critérios atingidos: ${dados.analiseLGPD.criteriosANPD.join(', ')}`, marginLeft + 15, y + 30, { width: contentWidth - 30 });
      y += 75;
    }
    
    // Artigos aplicáveis
    doc.fillColor(CORES.primaria)
       .font(FONTES.subtitulo)
       .fontSize(14)
       .text('Artigos da LGPD Aplicáveis', marginLeft, y);
    
    y += 25;
    
    dados.analiseLGPD.artigosAplicaveis.forEach(artigo => {
      if (y > doc.page.height - 150) {
        doc.addPage();
        y = 50;
      }
      
      doc.roundedRect(marginLeft, y, contentWidth, 80, 5).fill(CORES.fundo);
      doc.rect(marginLeft, y, 4, 80).fill(CORES.alto);
      
      doc.fillColor(CORES.primaria)
         .font(FONTES.negrito)
         .fontSize(11)
         .text(artigo.artigo, marginLeft + 15, y + 10, { width: contentWidth - 30 });
      
      doc.fillColor(CORES.texto)
         .font(FONTES.corpo)
         .fontSize(9)
         .text(artigo.descricao, marginLeft + 15, y + 30, { width: contentWidth - 30 });
      
      doc.fillColor(CORES.destaque)
         .font(FONTES.negrito)
         .fontSize(8)
         .text(`Achados relacionados: ${artigo.achadosRelacionados}`, marginLeft + 15, y + 60);
      
      y += 95;
    });
    
    // Recomendações LGPD
    y += 20;
    doc.fillColor(CORES.primaria)
       .font(FONTES.subtitulo)
       .fontSize(14)
       .text('Recomendações de Conformidade', marginLeft, y);
    
    y += 25;
    
    dados.analiseLGPD.recomendacoes.forEach((rec, i) => {
      if (y > doc.page.height - 50) {
        doc.addPage();
        y = 50;
      }
      
      doc.fillColor(CORES.destaque)
         .font(FONTES.negrito)
         .fontSize(10)
         .text(`${i + 1}.`, marginLeft, y, { continued: true });
      doc.fillColor(CORES.texto)
         .font(FONTES.corpo)
         .text(` ${rec}`, { width: contentWidth - 20 });
      
      y += 25;
    });
  }
  
  // DPO
  y += 20;
  if (y > doc.page.height - 100) {
    doc.addPage();
    y = 50;
  }
  
  doc.fillColor(CORES.primaria)
     .font(FONTES.subtitulo)
     .fontSize(14)
     .text('Encarregado de Dados (DPO)', marginLeft, y);
  
  y += 25;
  
  if (dados.empresa.dpo?.nome) {
    doc.fillColor(CORES.texto)
       .font(FONTES.corpo)
       .fontSize(10)
       .text(`Nome: ${dados.empresa.dpo.nome}`, marginLeft, y);
    y += 15;
    if (dados.empresa.dpo.email) {
      doc.text(`E-mail: ${dados.empresa.dpo.email}`, marginLeft, y);
    }
  } else {
    doc.fillColor(CORES.alto)
       .font(FONTES.negrito)
       .fontSize(10)
       .text('⚠ Nenhum DPO cadastrado. A LGPD exige a indicação de um encarregado pelo tratamento de dados pessoais.', marginLeft, y, { width: contentWidth });
  }
}

function gerarPlanoAcao(doc: PDFKit.PDFDocument, dados: DadosRelatorio) {
  doc.addPage();
  
  const marginLeft = 50;
  const marginRight = 50;
  const contentWidth = doc.page.width - marginLeft - marginRight;
  let y = 50;
  
  // Cabeçalho
  doc.fillColor(CORES.primaria)
     .font(FONTES.titulo)
     .fontSize(24)
     .text('Plano de Ação Priorizado', marginLeft, y);
  
  y += 40;
  
  doc.moveTo(marginLeft, y).lineTo(doc.page.width - marginRight, y).strokeColor(CORES.destaque).lineWidth(2).stroke();
  y += 20;
  
  // Legenda de prazos
  doc.fillColor(CORES.texto)
     .font(FONTES.corpo)
     .fontSize(10)
     .text('Prazos sugeridos: Imediato (críticos) | 7 dias (altos) | 30 dias (médios) | 90 dias (baixos)', marginLeft, y);
  
  y += 30;
  
  // Ordenar achados por prioridade
  const ordemRisco: Record<NivelRisco, number> = {
    [NivelRisco.CRITICO]: 0,
    [NivelRisco.ALTO]: 1,
    [NivelRisco.MEDIO]: 2,
    [NivelRisco.BAIXO]: 3,
    [NivelRisco.INFORMATIVO]: 4,
  };
  
  const achadosComRecomendacao = dados.achados
    .filter(a => a.recomendacao)
    .sort((a, b) => ordemRisco[a.nivelRisco] - ordemRisco[b.nivelRisco]);
  
  // Tabela de ações
  const colunas = [
    { header: '#', width: 25 },
    { header: 'Prioridade', width: 65 },
    { header: 'Ação Recomendada', width: contentWidth - 165 },
    { header: 'Prazo', width: 75 },
  ];
  
  // Cabeçalho da tabela
  doc.rect(marginLeft, y, contentWidth, 25).fill(CORES.primaria);
  
  let xPos = marginLeft;
  colunas.forEach(col => {
    doc.fillColor(CORES.branco)
       .font(FONTES.negrito)
       .fontSize(9)
       .text(col.header, xPos + 5, y + 7, { width: col.width - 10 });
    xPos += col.width;
  });
  
  y += 25;
  
  // Linhas da tabela
  achadosComRecomendacao.slice(0, 20).forEach((achado, index) => {
    if (y > doc.page.height - 60) {
      doc.addPage();
      y = 50;
    }
    
    const rowHeight = 40;
    const bgColor = index % 2 === 0 ? CORES.branco : CORES.fundo;
    
    doc.rect(marginLeft, y, contentWidth, rowHeight).fill(bgColor);
    
    xPos = marginLeft;
    
    // Número
    doc.fillColor(CORES.texto)
       .font(FONTES.corpo)
       .fontSize(9)
       .text((index + 1).toString(), xPos + 5, y + 12, { width: colunas[0].width - 10 });
    xPos += colunas[0].width;
    
    // Prioridade
    const corPrioridade = obterCorRisco(achado.nivelRisco);
    doc.roundedRect(xPos + 5, y + 10, 50, 18, 3).fill(corPrioridade);
    doc.fillColor(CORES.branco)
       .font(FONTES.negrito)
       .fontSize(8)
       .text(obterLabelRisco(achado.nivelRisco), xPos + 8, y + 14, { width: 45, align: 'center' });
    xPos += colunas[1].width;
    
    // Ação
    doc.fillColor(CORES.texto)
       .font(FONTES.corpo)
       .fontSize(8)
       .text(achado.recomendacao!.substring(0, 100) + (achado.recomendacao!.length > 100 ? '...' : ''), xPos + 5, y + 8, { width: colunas[2].width - 10 });
    xPos += colunas[2].width;
    
    // Prazo
    let prazo = '30 dias';
    if (achado.nivelRisco === NivelRisco.CRITICO) prazo = 'Imediato';
    else if (achado.nivelRisco === NivelRisco.ALTO) prazo = '7 dias';
    else if (achado.nivelRisco === NivelRisco.MEDIO) prazo = '30 dias';
    else prazo = '90 dias';
    
    doc.fillColor(CORES.texto)
       .fontSize(9)
       .text(prazo, xPos + 5, y + 12, { width: colunas[3].width - 10 });
    
    y += rowHeight;
  });
  
  // Rodapé
  y += 20;
  doc.fillColor(CORES.textoClaro)
     .font(FONTES.corpo)
     .fontSize(9)
     .text('* Os prazos sugeridos são baseados na severidade dos achados e devem ser ajustados conforme a capacidade operacional da organização.', marginLeft, y, { width: contentWidth });
}

function gerarGlossario(doc: PDFKit.PDFDocument, dados: DadosRelatorio) {
  doc.addPage();
  
  const marginLeft = 50;
  const marginRight = 50;
  const contentWidth = doc.page.width - marginLeft - marginRight;
  let y = 50;
  
  // Cabeçalho
  doc.fillColor(CORES.primaria)
     .font(FONTES.titulo)
     .fontSize(24)
     .text('Glossário de Termos Técnicos', marginLeft, y);
  
  y += 40;
  
  doc.moveTo(marginLeft, y).lineTo(doc.page.width - marginRight, y).strokeColor(CORES.destaque).lineWidth(2).stroke();
  y += 20;
  
  // Extrair termos usados no relatório
  const textosRelatorio = dados.achados.map(a => 
    `${a.titulo} ${a.descricao || ''} ${a.recomendacao || ''}`
  ).join(' ');
  
  const termosUsados = extrairTermosGlossario(textosRelatorio);
  
  // Adicionar termos comuns sempre presentes
  const termosBase = ['LGPD', 'ANPD', 'DPO', 'Threat Intelligence', 'OSINT', 'MFA/2FA'];
  const todosTermos = [...new Set([...termosUsados, ...termosBase])].sort();
  
  // Renderizar glossário
  todosTermos.forEach(termo => {
    if (y > doc.page.height - 80) {
      doc.addPage();
      y = 50;
    }
    
    const definicao = GLOSSARIO[termo];
    if (!definicao) return;
    
    doc.fillColor(CORES.primaria)
       .font(FONTES.negrito)
       .fontSize(11)
       .text(termo, marginLeft, y);
    
    y += 15;
    
    doc.fillColor(CORES.texto)
       .font(FONTES.corpo)
       .fontSize(10)
       .text(definicao, marginLeft + 15, y, { width: contentWidth - 15 });
    
    y += 35;
  });
}

// ============================================================================
// FUNÇÃO PRINCIPAL DE GERAÇÃO
// ============================================================================

export async function gerarRelatorioPDF(varreduraId: string): Promise<Buffer> {
  // Buscar dados da varredura
  const varredura = await prisma.varredura.findUnique({
    where: { id: varreduraId },
    include: {
      empresa: {
        include: {
          dominios: true,
        },
      },
      ocorrenciasAchado: {
        include: {
          definicao: true,
        },
      },
      execucoesFonte: true,
    },
  });
  
  if (!varredura) {
    throw new Error('Varredura não encontrada');
  }
  
  // Preparar achados com classificação de vulnerabilidade
  const achados = varredura.ocorrenciasAchado.map(o => {
    const achado = {
      id: o.definicao.id,
      titulo: o.definicao.titulo,
      descricao: o.definicao.descricao,
      recomendacao: o.definicao.recomendacao,
      nivelRisco: o.definicao.nivelRisco,
      fonte: o.definicao.fonte,
      tipoEntidade: o.definicao.tipoEntidade,
      entidade: o.definicao.entidade,
      evidencia: o.definicao.evidencia as Record<string, unknown> | null,
      primeiraVezEm: o.definicao.primeiraVezEm,
      ultimaVezEm: o.definicao.ultimaVezEm,
      vulnClass: undefined as VulnClass | undefined,
      scoreDetalhado: undefined as ScoreResult | undefined,
    };
    
    // Classificar vulnerabilidade
    achado.vulnClass = classificarVulnerabilidade(achado);
    
    // Calcular score detalhado
    achado.scoreDetalhado = calcularScoreAvancado(achado);
    
    return achado;
  });
  
  // Calcular score geral
  const scoreGeral = achados.length > 0 
    ? Math.round(achados.reduce((sum, a) => sum + (a.scoreDetalhado?.scoreFinal || 0), 0) / achados.length)
    : 0;
  
  // Calcular eixos médios
  const eixosMedios = {
    exposure: achados.reduce((sum, a) => sum + (a.scoreDetalhado?.eixos.exposure || 0), 0) / Math.max(achados.length, 1),
    exploitability: achados.reduce((sum, a) => sum + (a.scoreDetalhado?.eixos.exploitability || 0), 0) / Math.max(achados.length, 1),
    dataSensitivity: achados.reduce((sum, a) => sum + (a.scoreDetalhado?.eixos.dataSensitivity || 0), 0) / Math.max(achados.length, 1),
    scale: achados.reduce((sum, a) => sum + (a.scoreDetalhado?.eixos.scale || 0), 0) / Math.max(achados.length, 1),
    confidence: achados.reduce((sum, a) => sum + (a.scoreDetalhado?.eixos.confidence || 0), 0) / Math.max(achados.length, 1),
  };
  
  // Análise LGPD
  const analiseLGPD = analisarConformidadeLGPD(achados);
  
  const dados: DadosRelatorio = {
    varredura: {
      id: varredura.id,
      criadoEm: varredura.criadoEm,
      iniciadaEm: varredura.iniciadaEm,
      concluidaEm: varredura.concluidaEm,
      escopo: varredura.escopo,
      totalAchados: varredura.totalAchados,
      achadosCriticos: varredura.achadosCriticos,
      achadosAltos: varredura.achadosAltos,
      achadosMedios: varredura.achadosMedios,
      achadosBaixos: varredura.achadosBaixos,
    },
    empresa: {
      nome: varredura.empresa.nome,
      nomeFantasia: varredura.empresa.nomeFantasia,
      cnpj: varredura.empresa.cnpj,
      setor: varredura.empresa.setor,
      dominios: varredura.empresa.dominios.map(d => d.dominio),
      dpo: varredura.empresa.nomeDpo ? {
        nome: varredura.empresa.nomeDpo,
        email: varredura.empresa.emailDpo,
      } : null,
    },
    achados,
    execucoesFonte: varredura.execucoesFonte.map(e => ({
      fonte: e.fonte,
      status: e.status,
      itensEncontrados: e.itensEncontrados ?? 0,
      duracaoMs: e.duracaoMs ?? 0,
      usouCache: e.usouCache,
      mensagemErro: e.mensagemErro,
    })),
    scoreRisco: scoreGeral,
    classificacaoRisco: obterClassificacaoScore(scoreGeral),
    scoreDetalhado: {
      scoreFinal: scoreGeral,
      nivel: obterClassificacaoScore(scoreGeral) as 'CRÍTICO' | 'ALTO' | 'MÉDIO' | 'BAIXO',
      eixos: eixosMedios,
      fatores: [],
    },
    analiseLGPD,
  };
  
  // Criar documento PDF
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    
    const doc = new PDFDocument({
      size: 'A4',
      margin: 50,
      info: {
        Title: `Relatório de Ameaças - ${dados.empresa.nome}`,
        Author: 'Sentinela TI',
        Subject: 'Relatório de Inteligência de Ameaças Cibernéticas',
        Keywords: 'segurança, ameaças, LGPD, threat intelligence',
        Creator: 'Sentinela TI Platform',
      },
    });
    
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    
    // Gerar seções do relatório
    gerarCapa(doc, dados);
    gerarResumoExecutivo(doc, dados);
    gerarSecaoAchados(doc, dados);
    gerarSecaoLGPD(doc, dados);
    gerarPlanoAcao(doc, dados);
    gerarGlossario(doc, dados);
    
    doc.end();
  });
}

// ============================================================================
// EXPORTAÇÕES
// ============================================================================

export { obterCorRisco, obterLabelRisco, obterCorScore, obterClassificacaoScore };
