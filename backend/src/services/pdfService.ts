// ============================================================================
// SENTINELA - Serviço de Geração de Relatórios PDF
// Gera relatórios profissionais com capa, resumo executivo, achados e LGPD
// ============================================================================

import PDFDocument from 'pdfkit';
import { prisma } from '../config/prisma';
import { NivelRisco, FonteInformacao } from '@prisma/client';

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
};

const FONTES = {
  titulo: 'Helvetica-Bold',
  subtitulo: 'Helvetica-Bold',
  corpo: 'Helvetica',
  negrito: 'Helvetica-Bold',
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

function calcularScoreRisco(achados: DadosRelatorio['achados']): { score: number; classificacao: string } {
  let pontos = 0;
  
  for (const achado of achados) {
    switch (achado.nivelRisco) {
      case NivelRisco.CRITICO: pontos += 25; break;
      case NivelRisco.ALTO: pontos += 15; break;
      case NivelRisco.MEDIO: pontos += 8; break;
      case NivelRisco.BAIXO: pontos += 3; break;
    }
  }
  
  // Normalizar para 0-100 (máximo de 100 pontos)
  const score = Math.min(100, pontos);
  
  let classificacao: string;
  if (score >= 80) classificacao = 'CRÍTICO';
  else if (score >= 60) classificacao = 'ALTO';
  else if (score >= 40) classificacao = 'MÉDIO';
  else if (score >= 20) classificacao = 'BAIXO';
  else classificacao = 'MÍNIMO';
  
  return { score, classificacao };
}

function obterCorScore(score: number): string {
  if (score >= 80) return CORES.critico;
  if (score >= 60) return CORES.alto;
  if (score >= 40) return CORES.medio;
  if (score >= 20) return CORES.baixo;
  return CORES.destaque;
}

// ============================================================================
// MAPEAMENTO LGPD
// ============================================================================

const LGPD_ARTIGOS: Record<string, { artigo: string; descricao: string; recomendacao: string }> = {
  'vazamento_dados': {
    artigo: 'Art. 48 - Comunicação de Incidentes',
    descricao: 'O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência de incidente de segurança que possa acarretar risco ou dano relevante aos titulares.',
    recomendacao: 'Notificar a ANPD em até 72 horas e comunicar os titulares afetados.',
  },
  'credenciais_expostas': {
    artigo: 'Art. 46 - Segurança dos Dados',
    descricao: 'Os agentes de tratamento devem adotar medidas de segurança, técnicas e administrativas aptas a proteger os dados pessoais.',
    recomendacao: 'Implementar autenticação multifator e políticas de senhas fortes.',
  },
  'infraestrutura_exposta': {
    artigo: 'Art. 46 - Segurança dos Dados',
    descricao: 'Proteção contra acessos não autorizados e situações acidentais ou ilícitas de destruição, perda, alteração ou comunicação.',
    recomendacao: 'Revisar configurações de firewall e implementar segmentação de rede.',
  },
  'phishing': {
    artigo: 'Art. 50 - Boas Práticas e Governança',
    descricao: 'Controladores e operadores podem formular regras de boas práticas e de governança.',
    recomendacao: 'Implementar treinamentos de conscientização e filtros anti-phishing.',
  },
  'malware': {
    artigo: 'Art. 46 - Segurança dos Dados',
    descricao: 'Adoção de medidas técnicas para proteção dos dados pessoais.',
    recomendacao: 'Implementar soluções de EDR/XDR e manter sistemas atualizados.',
  },
};

function obterArtigoLGPD(titulo: string): typeof LGPD_ARTIGOS[string] | null {
  const tipoNormalizado = titulo.toLowerCase();
  if (tipoNormalizado.includes('vazamento') || tipoNormalizado.includes('leak') || tipoNormalizado.includes('breach')) {
    return LGPD_ARTIGOS['vazamento_dados'];
  }
  if (tipoNormalizado.includes('credencial') || tipoNormalizado.includes('senha') || tipoNormalizado.includes('password') || tipoNormalizado.includes('infostealer')) {
    return LGPD_ARTIGOS['credenciais_expostas'];
  }
  if (tipoNormalizado.includes('porta') || tipoNormalizado.includes('serviço') || tipoNormalizado.includes('exposto') || tipoNormalizado.includes('cve')) {
    return LGPD_ARTIGOS['infraestrutura_exposta'];
  }
  if (tipoNormalizado.includes('phishing') || tipoNormalizado.includes('impersonation')) {
    return LGPD_ARTIGOS['phishing'];
  }
  if (tipoNormalizado.includes('malware') || tipoNormalizado.includes('virus') || tipoNormalizado.includes('ransomware')) {
    return LGPD_ARTIGOS['malware'];
  }
  return null;
}

// ============================================================================
// GERAÇÃO DO PDF
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
  doc.translate(centerX - 40, 150);
  doc.path('M40 0 L80 20 L80 50 C80 80 40 100 40 100 C40 100 0 80 0 50 L0 20 Z')
     .fill(CORES.destaque);
  doc.path('M40 15 L65 30 L65 48 C65 68 40 82 40 82 C40 82 15 68 15 48 L15 30 Z')
     .fill(CORES.primaria);
  doc.restore();
  
  // Título
  doc.fillColor(CORES.branco)
     .font(FONTES.titulo)
     .fontSize(42)
     .text('SENTINELA TI', 0, 280, { align: 'center' });
  
  doc.fontSize(16)
     .font(FONTES.corpo)
     .text('Relatório de Inteligência de Ameaças', 0, 330, { align: 'center' });
  
  // Nome da empresa
  doc.fontSize(28)
     .font(FONTES.titulo)
     .text(dados.empresa.nome, 0, 400, { align: 'center' });
  
  if (dados.empresa.cnpj) {
    doc.fontSize(12)
       .font(FONTES.corpo)
       .fillColor(CORES.textoClaro)
       .text(`CNPJ: ${dados.empresa.cnpj}`, 0, 440, { align: 'center' });
  }
  
  // Score de Risco Visual
  const scoreY = 500;
  const scoreColor = obterCorScore(dados.scoreRisco);
  
  doc.fillColor(CORES.branco)
     .font(FONTES.subtitulo)
     .fontSize(14)
     .text('SCORE DE RISCO', 0, scoreY, { align: 'center' });
  
  // Círculo do score
  doc.circle(centerX, scoreY + 70, 50)
     .lineWidth(8)
     .strokeColor(scoreColor)
     .stroke();
  
  doc.fillColor(scoreColor)
     .font(FONTES.titulo)
     .fontSize(36)
     .text(dados.scoreRisco.toString(), centerX - 25, scoreY + 50, { width: 50, align: 'center' });
  
  doc.fillColor(CORES.branco)
     .font(FONTES.negrito)
     .fontSize(16)
     .text(dados.classificacaoRisco, 0, scoreY + 140, { align: 'center' });
  
  // Data do relatório
  doc.fillColor(CORES.textoClaro)
     .font(FONTES.corpo)
     .fontSize(12)
     .text(`Gerado em: ${formatarData(new Date())}`, 0, pageHeight - 100, { align: 'center' });
  
  doc.text(`Período da varredura: ${formatarDataCurta(dados.varredura.criadoEm)}`, 0, pageHeight - 80, { align: 'center' });
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
  
  // Linha divisória
  doc.moveTo(marginLeft, y).lineTo(doc.page.width - marginRight, y).strokeColor(CORES.destaque).lineWidth(2).stroke();
  y += 20;
  
  // Cards de métricas
  const cardWidth = (contentWidth - 30) / 4;
  const cardHeight = 80;
  const cards = [
    { label: 'Total de Achados', valor: dados.varredura.totalAchados.toString(), cor: CORES.primaria },
    { label: 'Críticos', valor: dados.varredura.achadosCriticos.toString(), cor: CORES.critico },
    { label: 'Altos', valor: dados.varredura.achadosAltos.toString(), cor: CORES.alto },
    { label: 'Médios', valor: dados.varredura.achadosMedios.toString(), cor: CORES.medio },
  ];
  
  cards.forEach((card, i) => {
    const x = marginLeft + i * (cardWidth + 10);
    
    doc.roundedRect(x, y, cardWidth, cardHeight, 5)
       .fill(card.cor);
    
    doc.fillColor(CORES.branco)
       .font(FONTES.titulo)
       .fontSize(28)
       .text(card.valor, x, y + 15, { width: cardWidth, align: 'center' });
    
    doc.fontSize(10)
       .font(FONTES.corpo)
       .text(card.label, x, y + 50, { width: cardWidth, align: 'center' });
  });
  
  y += cardHeight + 30;
  
  // Informações da empresa
  doc.fillColor(CORES.texto)
     .font(FONTES.subtitulo)
     .fontSize(14)
     .text('Informações da Empresa', marginLeft, y);
  
  y += 25;
  
  const infoEmpresa = [
    ['Razão Social', dados.empresa.nome],
    ['Nome Fantasia', dados.empresa.nomeFantasia || 'N/A'],
    ['CNPJ', dados.empresa.cnpj || 'N/A'],
    ['Setor', dados.empresa.setor || 'N/A'],
    ['Domínios Monitorados', dados.empresa.dominios.join(', ') || 'N/A'],
  ];
  
  infoEmpresa.forEach(([label, valor]) => {
    doc.font(FONTES.negrito).fontSize(10).text(`${label}:`, marginLeft, y, { continued: true });
    doc.font(FONTES.corpo).text(` ${valor}`);
    y += 18;
  });
  
  y += 20;
  
  // Informações da varredura
  doc.font(FONTES.subtitulo)
     .fontSize(14)
     .text('Informações da Varredura', marginLeft, y);
  
  y += 25;
  
  const infoVarredura = [
    ['ID da Varredura', dados.varredura.id],
    ['Escopo', dados.varredura.escopo],
    ['Iniciada em', formatarData(dados.varredura.iniciadaEm)],
    ['Concluída em', formatarData(dados.varredura.concluidaEm)],
    ['Fontes Consultadas', dados.execucoesFonte.length.toString()],
  ];
  
  infoVarredura.forEach(([label, valor]) => {
    doc.font(FONTES.negrito).fontSize(10).text(`${label}:`, marginLeft, y, { continued: true });
    doc.font(FONTES.corpo).text(` ${valor}`);
    y += 18;
  });
  
  y += 30;
  
  // Distribuição por fonte
  doc.font(FONTES.subtitulo)
     .fontSize(14)
     .text('Fontes de Inteligência Consultadas', marginLeft, y);
  
  y += 20;
  
  const fontesAgrupadas: Record<string, { sucesso: number; erro: number; itens: number }> = {};
  dados.execucoesFonte.forEach(exec => {
    if (!fontesAgrupadas[exec.fonte]) {
      fontesAgrupadas[exec.fonte] = { sucesso: 0, erro: 0, itens: 0 };
    }
    if (exec.status === 'SUCESSO' || exec.status === 'CACHE') {
      fontesAgrupadas[exec.fonte].sucesso++;
    } else {
      fontesAgrupadas[exec.fonte].erro++;
    }
    fontesAgrupadas[exec.fonte].itens += exec.itensEncontrados;
  });
  
  Object.entries(fontesAgrupadas).forEach(([fonte, stats]) => {
    const statusIcon = stats.erro === 0 ? '✓' : stats.sucesso > 0 ? '⚠' : '✗';
    const statusColor = stats.erro === 0 ? CORES.destaque : stats.sucesso > 0 ? CORES.medio : CORES.critico;
    
    doc.fillColor(statusColor).font(FONTES.negrito).fontSize(10).text(statusIcon, marginLeft, y, { continued: true });
    doc.fillColor(CORES.texto).font(FONTES.corpo).text(` ${fonte} - ${stats.itens} itens encontrados`);
    y += 16;
  });
}

function gerarSecaoAchados(doc: PDFKit.PDFDocument, dados: DadosRelatorio) {
  const marginLeft = 50;
  const marginRight = 50;
  const contentWidth = doc.page.width - marginLeft - marginRight;
  
  // Ordenar achados por severidade
  const ordemRisco: Record<NivelRisco, number> = {
    [NivelRisco.CRITICO]: 0,
    [NivelRisco.ALTO]: 1,
    [NivelRisco.MEDIO]: 2,
    [NivelRisco.BAIXO]: 3,
    [NivelRisco.INFORMATIVO]: 4,
  };
  
  const achadosOrdenados = [...dados.achados].sort((a, b) => ordemRisco[a.nivelRisco] - ordemRisco[b.nivelRisco]);
  
  // Agrupar por nível de risco
  const grupos: Record<NivelRisco, typeof achadosOrdenados> = {
    [NivelRisco.CRITICO]: [],
    [NivelRisco.ALTO]: [],
    [NivelRisco.MEDIO]: [],
    [NivelRisco.BAIXO]: [],
    [NivelRisco.INFORMATIVO]: [],
  };
  
  achadosOrdenados.forEach(achado => {
    grupos[achado.nivelRisco].push(achado);
  });
  
  // Gerar seção para cada nível de risco
  const niveisComAchados = Object.entries(grupos).filter(([_, achados]) => achados.length > 0);
  
  niveisComAchados.forEach(([nivel, achados]) => {
    doc.addPage();
    let y = 50;
    
    // Cabeçalho do grupo
    const corNivel = obterCorRisco(nivel as NivelRisco);
    const labelNivel = obterLabelRisco(nivel as NivelRisco);
    
    doc.roundedRect(marginLeft, y, contentWidth, 40, 5).fill(corNivel);
    
    doc.fillColor(CORES.branco)
       .font(FONTES.titulo)
       .fontSize(18)
       .text(`Achados de Risco ${labelNivel}`, marginLeft + 15, y + 10);
    
    doc.fontSize(12)
       .text(`${achados.length} achado(s)`, doc.page.width - marginRight - 100, y + 12, { width: 85, align: 'right' });
    
    y += 55;
    
    // Listar achados
    achados.forEach((achado) => {
      // Verificar se precisa de nova página
      if (y > doc.page.height - 200) {
        doc.addPage();
        y = 50;
      }
      
      // Card do achado
      const cardY = y;
      
      // Barra lateral colorida
      doc.rect(marginLeft, cardY, 4, 120).fill(corNivel);
      
      // Fundo do card
      doc.rect(marginLeft + 4, cardY, contentWidth - 4, 120).fill(CORES.fundo);
      
      // Título
      doc.fillColor(CORES.texto)
         .font(FONTES.negrito)
         .fontSize(12)
         .text(achado.titulo, marginLeft + 15, cardY + 10, { width: contentWidth - 30 });
      
      // Metadados
      doc.fillColor(CORES.textoClaro)
         .font(FONTES.corpo)
         .fontSize(9)
         .text(`Fonte: ${achado.fonte} | Entidade: ${achado.entidade} | Detectado: ${formatarDataCurta(achado.primeiraVezEm)}`, marginLeft + 15, cardY + 30);
      
      // Descrição
      if (achado.descricao) {
        doc.fillColor(CORES.texto)
           .fontSize(10)
           .text(achado.descricao.substring(0, 200) + (achado.descricao.length > 200 ? '...' : ''), marginLeft + 15, cardY + 48, { width: contentWidth - 30 });
      }
      
      // Recomendação
      if (achado.recomendacao) {
        doc.fillColor(CORES.destaque)
           .font(FONTES.negrito)
           .fontSize(9)
           .text('Recomendação:', marginLeft + 15, cardY + 85, { continued: true });
        doc.font(FONTES.corpo)
           .fillColor(CORES.texto)
           .text(` ${achado.recomendacao.substring(0, 150)}${achado.recomendacao.length > 150 ? '...' : ''}`);
      }
      
      y += 135;
    });
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
     .text('A Lei Geral de Proteção de Dados (Lei nº 13.709/2018) estabelece regras sobre coleta, armazenamento, tratamento e compartilhamento de dados pessoais. Os achados identificados nesta varredura podem ter implicações diretas na conformidade com a LGPD.', marginLeft, y, { width: contentWidth, align: 'justify' });
  
  y += 60;
  
  // Mapear achados para artigos da LGPD
  const artigosRelevantes = new Map<string, { artigo: typeof LGPD_ARTIGOS[string]; achados: string[] }>();
  
  dados.achados.forEach(achado => {
    const artigoInfo = obterArtigoLGPD(achado.titulo);
    if (artigoInfo) {
      const key = artigoInfo.artigo;
      if (!artigosRelevantes.has(key)) {
        artigosRelevantes.set(key, { artigo: artigoInfo, achados: [] });
      }
      artigosRelevantes.get(key)!.achados.push(achado.titulo);
    }
  });
  
  if (artigosRelevantes.size === 0) {
    doc.fillColor(CORES.destaque)
       .font(FONTES.negrito)
       .fontSize(12)
       .text('✓ Nenhuma violação direta de LGPD identificada nos achados.', marginLeft, y);
    y += 30;
  } else {
    artigosRelevantes.forEach((info) => {
      if (y > doc.page.height - 200) {
        doc.addPage();
        y = 50;
      }
      
      // Card do artigo
      doc.roundedRect(marginLeft, y, contentWidth, 120, 5).fill(CORES.fundo);
      doc.rect(marginLeft, y, 4, 120).fill(CORES.alto);
      
      doc.fillColor(CORES.primaria)
         .font(FONTES.negrito)
         .fontSize(12)
         .text(info.artigo.artigo, marginLeft + 15, y + 10, { width: contentWidth - 30 });
      
      doc.fillColor(CORES.texto)
         .font(FONTES.corpo)
         .fontSize(10)
         .text(info.artigo.descricao, marginLeft + 15, y + 30, { width: contentWidth - 30 });
      
      doc.fillColor(CORES.destaque)
         .font(FONTES.negrito)
         .fontSize(9)
         .text('Recomendação LGPD:', marginLeft + 15, y + 70, { continued: true });
      doc.font(FONTES.corpo)
         .fillColor(CORES.texto)
         .text(` ${info.artigo.recomendacao}`);
      
      doc.fillColor(CORES.textoClaro)
         .fontSize(8)
         .text(`Achados relacionados: ${info.achados.length}`, marginLeft + 15, y + 100);
      
      y += 135;
    });
  }
  
  // Seção de DPO
  y += 20;
  if (y > doc.page.height - 150) {
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
    { header: '#', width: 30 },
    { header: 'Prioridade', width: 70 },
    { header: 'Ação Recomendada', width: contentWidth - 180 },
    { header: 'Prazo Sugerido', width: 80 },
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
  achadosComRecomendacao.slice(0, 15).forEach((achado, index) => {
    if (y > doc.page.height - 80) {
      doc.addPage();
      y = 50;
    }
    
    const rowHeight = 35;
    const bgColor = index % 2 === 0 ? CORES.branco : CORES.fundo;
    
    doc.rect(marginLeft, y, contentWidth, rowHeight).fill(bgColor);
    
    xPos = marginLeft;
    
    // Número
    doc.fillColor(CORES.texto)
       .font(FONTES.corpo)
       .fontSize(9)
       .text((index + 1).toString(), xPos + 5, y + 10, { width: colunas[0].width - 10 });
    xPos += colunas[0].width;
    
    // Prioridade
    const corPrioridade = obterCorRisco(achado.nivelRisco);
    doc.roundedRect(xPos + 5, y + 8, 55, 18, 3).fill(corPrioridade);
    doc.fillColor(CORES.branco)
       .font(FONTES.negrito)
       .fontSize(8)
       .text(obterLabelRisco(achado.nivelRisco), xPos + 8, y + 12, { width: 50, align: 'center' });
    xPos += colunas[1].width;
    
    // Ação
    doc.fillColor(CORES.texto)
       .font(FONTES.corpo)
       .fontSize(8)
       .text(achado.recomendacao!.substring(0, 80) + (achado.recomendacao!.length > 80 ? '...' : ''), xPos + 5, y + 10, { width: colunas[2].width - 10 });
    xPos += colunas[2].width;
    
    // Prazo
    let prazo = '30 dias';
    if (achado.nivelRisco === NivelRisco.CRITICO) prazo = 'Imediato';
    else if (achado.nivelRisco === NivelRisco.ALTO) prazo = '7 dias';
    else if (achado.nivelRisco === NivelRisco.MEDIO) prazo = '30 dias';
    else prazo = '90 dias';
    
    doc.fillColor(CORES.texto)
       .fontSize(9)
       .text(prazo, xPos + 5, y + 10, { width: colunas[3].width - 10 });
    
    y += rowHeight;
  });
  
  // Rodapé
  y += 30;
  doc.fillColor(CORES.textoClaro)
     .font(FONTES.corpo)
     .fontSize(9)
     .text('* Os prazos sugeridos são baseados na severidade dos achados e devem ser ajustados conforme a capacidade operacional da organização.', marginLeft, y, { width: contentWidth });
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
  
  // Preparar dados
  const achados = varredura.ocorrenciasAchado.map(o => ({
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
  }));
  
  const { score, classificacao } = calcularScoreRisco(achados);
  
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
    scoreRisco: score,
    classificacaoRisco: classificacao,
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
    
    doc.end();
  });
}

// ============================================================================
// EXPORTAÇÕES
// ============================================================================

export { calcularScoreRisco, obterCorRisco, obterLabelRisco };
