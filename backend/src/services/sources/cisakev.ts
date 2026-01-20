// ============================================================================
// SENTINELA - Integração com CISA KEV (Known Exploited Vulnerabilities)
// Catálogo de vulnerabilidades ativamente exploradas
// API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// ============================================================================

import axios from 'axios';
import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { AchadoCandidato, ResultadoFonte } from '../../types';

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface CISAVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
}

interface CISAKEVResponse {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CISAVulnerability[];
}

// Cache do catálogo KEV (atualizado a cada 24h)
let kevCache: { data: CISAKEVResponse; timestamp: number } | null = null;
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 horas

async function obterCatalogoKEV(): Promise<CISAKEVResponse> {
  const agora = Date.now();
  
  if (kevCache && (agora - kevCache.timestamp) < CACHE_TTL) {
    return kevCache.data;
  }
  
  const response = await axios.get<CISAKEVResponse>(CISA_KEV_URL, {
    timeout: 30000,
  });
  
  kevCache = {
    data: response.data,
    timestamp: agora,
  };
  
  return response.data;
}

// Verificar CVEs de um produto/vendor específico
export async function verificarCVEsExploradas(
  produtos: string[],
  vendors: string[]
): Promise<ResultadoFonte> {
  const achados: AchadoCandidato[] = [];
  
  try {
    const catalogo = await obterCatalogoKEV();
    
    // Normalizar termos de busca
    const produtosNorm = produtos.map(p => p.toLowerCase());
    const vendorsNorm = vendors.map(v => v.toLowerCase());
    
    // Filtrar vulnerabilidades relevantes
    const vulnsRelevantes = catalogo.vulnerabilities.filter(vuln => {
      const vendorLower = vuln.vendorProject.toLowerCase();
      const productLower = vuln.product.toLowerCase();
      
      return vendorsNorm.some(v => vendorLower.includes(v) || v.includes(vendorLower)) ||
             produtosNorm.some(p => productLower.includes(p) || p.includes(productLower));
    });
    
    if (vulnsRelevantes.length > 0) {
      // Agrupar por vendor/produto
      const porVendor: Record<string, CISAVulnerability[]> = {};
      
      vulnsRelevantes.forEach(vuln => {
        const key = `${vuln.vendorProject} - ${vuln.product}`;
        if (!porVendor[key]) {
          porVendor[key] = [];
        }
        porVendor[key].push(vuln);
      });
      
      Object.entries(porVendor).forEach(([key, vulns]) => {
        const comRansomware = vulns.filter(v => v.knownRansomwareCampaignUse === 'Known');
        const recentes = vulns.filter(v => {
          const dataAdicionada = new Date(v.dateAdded);
          const hoje = new Date();
          const diasAtras = (hoje.getTime() - dataAdicionada.getTime()) / (1000 * 60 * 60 * 24);
          return diasAtras <= 90;
        });
        
        // Determinar severidade: Ransomware = CRITICO, senão ALTO
        const nivelRisco = comRansomware.length > 0 ? NivelRisco.CRITICO : NivelRisco.ALTO;
        
        const descricao = `Foram identificadas ${vulns.length} vulnerabilidade(s) ativamente exploradas ` +
          `no catálogo CISA KEV para "${key}". ` +
          `${comRansomware.length > 0 ? `⚠️ ${comRansomware.length} usada(s) em campanhas de ransomware. ` : ''}` +
          `${recentes.length > 0 ? `${recentes.length} adicionada(s) nos últimos 90 dias. ` : ''}` +
          `CVEs: ${vulns.slice(0, 5).map(v => v.cveID).join(', ')}${vulns.length > 5 ? '...' : ''}.`;
        
        achados.push({
          fonte: FonteInformacao.VIRUSTOTAL, // Usando VT como proxy
          nivelRisco,
          tipo: 'cve_explorada',
          tipoEntidade: TipoEntidade.TEXTO, // Usando TEXTO como proxy para serviços/produtos
          entidade: key,
          titulo: `CVEs Ativamente Exploradas: ${key}`,
          descricao,
          recomendacao: comRansomware.length > 0
            ? 'CRÍTICO: Vulnerabilidades usadas em ransomware detectadas. Aplique patches IMEDIATAMENTE ou implemente mitigações temporárias.'
            : 'Priorize a aplicação de patches para estas vulnerabilidades. Verifique se os produtos afetados estão em uso na sua infraestrutura.',
          evidencia: {
            vendorProduto: key,
            totalCVEs: vulns.length,
            usadasEmRansomware: comRansomware.length,
            adicionadasRecentemente: recentes.length,
            cves: vulns.map(v => ({
              cveId: v.cveID,
              nome: v.vulnerabilityName,
              descricao: v.shortDescription,
              acaoRequerida: v.requiredAction,
              dataAdicionada: v.dateAdded,
              prazoRemediacao: v.dueDate,
              ransomware: v.knownRansomwareCampaignUse === 'Known',
            })),
          },
        });
      });
    }
    
    return {
      achados,
      itensEncontrados: achados.length,
      metadados: {
        fonte: 'CISA KEV',
        versaoCatalogo: catalogo.catalogVersion,
        dataLancamento: catalogo.dateReleased,
        totalVulnerabilidades: catalogo.count,
        produtosBuscados: produtos,
        vendorsBuscados: vendors,
      },
    };
  } catch (erro: any) {
    console.error('Erro ao consultar CISA KEV:', erro.message);
    throw erro;
  }
}

// Obter vulnerabilidades recentes (últimos N dias)
export async function obterCVEsRecentes(dias: number = 30): Promise<CISAVulnerability[]> {
  try {
    const catalogo = await obterCatalogoKEV();
    const hoje = new Date();
    
    return catalogo.vulnerabilities.filter(vuln => {
      const dataAdicionada = new Date(vuln.dateAdded);
      const diasAtras = (hoje.getTime() - dataAdicionada.getTime()) / (1000 * 60 * 60 * 24);
      return diasAtras <= dias;
    });
  } catch {
    return [];
  }
}

// Obter estatísticas do catálogo
export async function obterEstatisticasKEV(): Promise<{
  total: number;
  comRansomware: number;
  ultimos30Dias: number;
  ultimos90Dias: number;
  topVendors: { vendor: string; count: number }[];
}> {
  try {
    const catalogo = await obterCatalogoKEV();
    const hoje = new Date();
    
    const comRansomware = catalogo.vulnerabilities.filter(v => v.knownRansomwareCampaignUse === 'Known').length;
    
    const ultimos30Dias = catalogo.vulnerabilities.filter(v => {
      const dias = (hoje.getTime() - new Date(v.dateAdded).getTime()) / (1000 * 60 * 60 * 24);
      return dias <= 30;
    }).length;
    
    const ultimos90Dias = catalogo.vulnerabilities.filter(v => {
      const dias = (hoje.getTime() - new Date(v.dateAdded).getTime()) / (1000 * 60 * 60 * 24);
      return dias <= 90;
    }).length;
    
    // Top vendors
    const vendorCount: Record<string, number> = {};
    catalogo.vulnerabilities.forEach(v => {
      vendorCount[v.vendorProject] = (vendorCount[v.vendorProject] || 0) + 1;
    });
    
    const topVendors = Object.entries(vendorCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([vendor, count]) => ({ vendor, count }));
    
    return {
      total: catalogo.count,
      comRansomware,
      ultimos30Dias,
      ultimos90Dias,
      topVendors,
    };
  } catch {
    return {
      total: 0,
      comRansomware: 0,
      ultimos30Dias: 0,
      ultimos90Dias: 0,
      topVendors: [],
    };
  }
}
