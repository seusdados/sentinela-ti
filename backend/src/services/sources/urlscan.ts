// ============================================================================
// SENTINELA - Fonte: URLScan (Detecção de Phishing e Impersonação)
// ============================================================================
// 
// O URLScan.io é uma ferramenta de análise de URLs que captura screenshots,
// analisa o conteúdo e detecta comportamentos maliciosos. É especialmente
// útil para identificar tentativas de phishing e impersonação de marca.
//
// UTILIDADE: Detectar ameaças à marca da empresa:
// - Sites de phishing imitando a empresa
// - Domínios typosquatting (ex: empres4.com vs empresa.com)
// - Páginas maliciosas usando a marca
// - Campanhas de phishing ativas
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoURLScan {
  results: {
    task: {
      url: string;
      time: string;
      visibility: string;
    };
    page: {
      domain: string;
      url: string;
      ip?: string;
      country?: string;
      server?: string;
      mimeType?: string;
    };
    result?: string;
    screenshot?: string;
    verdicts: {
      overall: {
        score: number;
        malicious: boolean;
        hasVerdicts: boolean;
      };
      urlscan?: {
        score: number;
        malicious: boolean;
        categories?: string[];
      };
      engines?: {
        malicious: string[];
        benign: string[];
      };
    };
  }[];
  total: number;
}

export async function buscarAmeacasMarca(dominio: string, chaveApi?: string | null): Promise<ResultadoFonte> {
  // Busca por URLs que mencionam o domínio
  const consulta = `domain:${dominio}`;
  const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(consulta)}&size=100`;
  
  const headers: Record<string, string> = {};
  if (chaveApi) {
    headers['API-Key'] = chaveApi;
  }
  
  const resposta = await http.get<ResultadoURLScan>(url, { headers });
  
  if (!resposta.sucesso) {
    throw new Error(resposta.erro?.mensagem || 'Erro ao consultar URLScan');
  }
  
  const resultados = resposta.dados?.results || [];
  const achados: AchadoCandidato[] = [];
  
  // Extrair o domínio base para comparação
  const dominioBase = dominio.toLowerCase();
  
  for (const resultado of resultados) {
    const pagina = resultado.page;
    const tarefa = resultado.task;
    const vereditos = resultado.verdicts;
    
    const hostnameScan = String(pagina?.domain || '').toLowerCase();
    const urlScan = String(tarefa?.url || '').toLowerCase();
    const screenshot = resultado.screenshot;
    const vereiditoGeral = vereditos?.overall;
    const pontuacao = vereiditoGeral?.score || 0;
    
    // Verificar se é um domínio de impersonação (contém o nome mas não é subdomínio legítimo)
    const isSubdominioLegitimo = hostnameScan === dominioBase || 
                                  hostnameScan.endsWith(`.${dominioBase}`);
    const contemNomeDominio = hostnameScan.includes(dominioBase.split('.')[0]);
    
    if (contemNomeDominio && !isSubdominioLegitimo) {
      // Possível impersonação/typosquatting
      achados.push({
        fonte: FonteInformacao.URLSCAN,
        nivelRisco: NivelRisco.ALTO,
        tipo: 'dominio_impersonacao',
        tipoEntidade: TipoEntidade.DOMINIO,
        entidade: hostnameScan,
        titulo: `Possível domínio de impersonação detectado: ${hostnameScan}`,
        descricao: `O domínio "${hostnameScan}" foi encontrado em uma varredura pública e contém parte do nome da sua empresa, mas não é um subdomínio legítimo. Isso pode indicar uma tentativa de phishing, typosquatting ou impersonação de marca. A URL escaneada foi: ${urlScan}`,
        recomendacao: 'Investigue este domínio para determinar se está sendo usado para phishing ou fraude. Considere registrar variações do seu domínio para prevenção. Se confirmado como malicioso, reporte aos registradores e às plataformas de segurança.',
        evidencia: {
          dominioSuspeito: hostnameScan,
          urlCompleta: urlScan,
          screenshot,
          resultadoScan: resultado.result,
          dataEscaneamento: tarefa?.time,
          pontuacaoMaliciosa: pontuacao,
        },
      });
    }
    
    // Verificar URLs com pontuação maliciosa alta no próprio domínio
    if (pontuacao >= 60 && isSubdominioLegitimo) {
      achados.push({
        fonte: FonteInformacao.URLSCAN,
        nivelRisco: pontuacao >= 80 ? NivelRisco.CRITICO : NivelRisco.ALTO,
        tipo: 'url_maliciosa',
        tipoEntidade: TipoEntidade.URL,
        entidade: urlScan || hostnameScan,
        titulo: `URL do seu domínio marcada como maliciosa pelo URLScan`,
        descricao: `Uma URL do seu domínio (${hostnameScan}) recebeu pontuação de risco ${pontuacao}/100 no URLScan. ${vereiditoGeral?.malicious ? 'O sistema classificou esta URL como MALICIOSA.' : 'A URL apresenta comportamentos suspeitos.'} Isso pode indicar que seu site foi comprometido ou está sendo usado para hospedar conteúdo malicioso.`,
        recomendacao: 'URGENTE: Investigue imediatamente esta URL. Verifique se há malware, scripts maliciosos injetados ou páginas de phishing hospedadas no seu servidor. Analise logs de acesso para identificar como a ameaça foi inserida.',
        evidencia: {
          url: urlScan,
          hostname: hostnameScan,
          pontuacao,
          malicioso: vereiditoGeral?.malicious,
          categorias: vereditos?.urlscan?.categories,
          enginesDetectaram: vereditos?.engines?.malicious,
          screenshot,
          resultadoScan: resultado.result,
          dataEscaneamento: tarefa?.time,
        },
      });
    }
  }
  
  return {
    achados,
    itensEncontrados: resultados.length,
    metadados: {
      totalResultados: resposta.dados?.total || resultados.length,
      dominiosBuscados: [...new Set(resultados.map(r => r.page?.domain))].filter(Boolean),
    },
  };
}
