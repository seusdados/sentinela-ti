// ============================================================================
// SENTINELA - Integração com Ransomware.live
// Detecta se a empresa foi vítima de ransomware
// API: https://api.ransomware.live/
// ============================================================================

import axios from 'axios';
import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { AchadoCandidato, ResultadoFonte } from '../../types';

const RANSOMWARE_API = 'https://api.ransomware.live';

interface RansomwareVictim {
  victim: string;
  group: string;
  discovered: string;
  published: string;
  country: string;
  website: string;
  description: string;
  post_url: string;
}

export async function buscarVitimasRansomware(dominio: string, nomeEmpresa?: string): Promise<ResultadoFonte> {
  const achados: AchadoCandidato[] = [];
  
  try {
    // Buscar vítimas recentes (últimos 365 dias)
    const response = await axios.get<RansomwareVictim[]>(
      `${RANSOMWARE_API}/recentvictims`,
      {
        timeout: 30000,
      }
    );
    
    const vitimas = response.data;
    
    // Filtrar por domínio ou nome da empresa
    const dominioBase = dominio.replace(/^www\./, '').toLowerCase();
    const termosBusca = [dominioBase];
    
    if (nomeEmpresa) {
      // Adicionar variações do nome da empresa
      termosBusca.push(nomeEmpresa.toLowerCase());
      termosBusca.push(nomeEmpresa.toLowerCase().replace(/\s+/g, ''));
      termosBusca.push(nomeEmpresa.toLowerCase().replace(/\s+/g, '-'));
    }
    
    const vitimasEncontradas = vitimas.filter(v => {
      const vitimaLower = v.victim.toLowerCase();
      const websiteLower = (v.website || '').toLowerCase();
      
      return termosBusca.some(termo => 
        vitimaLower.includes(termo) || 
        websiteLower.includes(termo) ||
        termo.includes(vitimaLower)
      );
    });
    
    if (vitimasEncontradas.length > 0) {
      // Agrupar por grupo de ransomware
      const porGrupo: Record<string, RansomwareVictim[]> = {};
      
      vitimasEncontradas.forEach(v => {
        if (!porGrupo[v.group]) {
          porGrupo[v.group] = [];
        }
        porGrupo[v.group].push(v);
      });
      
      Object.entries(porGrupo).forEach(([grupo, vitimas]) => {
        const vitimaRecente = vitimas.reduce((max, v) => 
          v.discovered > max.discovered ? v : max, vitimas[0]
        );
        
        const descricao = `A empresa foi identificada como vítima do grupo de ransomware "${grupo}". ` +
          `Data de descoberta: ${vitimaRecente.discovered}. ` +
          `País registrado: ${vitimaRecente.country || 'N/A'}. ` +
          `${vitimaRecente.description ? `Descrição: ${vitimaRecente.description.substring(0, 200)}...` : ''}`;
        
        achados.push({
          fonte: FonteInformacao.LEAKIX, // Usando LEAKIX como proxy
          nivelRisco: NivelRisco.CRITICO,
          tipo: 'ransomware_victim',
          tipoEntidade: TipoEntidade.DOMINIO, // Usando DOMINIO como proxy para organização
          entidade: dominio,
          titulo: `Vítima de Ransomware: ${grupo}`,
          descricao,
          recomendacao: 'CRÍTICO: Sua organização foi identificada como vítima de ransomware. ' +
            'Ações imediatas: 1) Ativar plano de resposta a incidentes; ' +
            '2) Isolar sistemas afetados; ' +
            '3) Notificar autoridades (ANPD, polícia); ' +
            '4) Avaliar extensão do vazamento; ' +
            '5) Comunicar stakeholders conforme LGPD Art. 48.',
          evidencia: {
            grupoRansomware: grupo,
            nomeVitima: vitimaRecente.victim,
            dataDescoberta: vitimaRecente.discovered,
            dataPublicacao: vitimaRecente.published,
            pais: vitimaRecente.country,
            website: vitimaRecente.website,
            urlPost: vitimaRecente.post_url,
            descricaoOriginal: vitimaRecente.description,
            totalOcorrencias: vitimas.length,
          },
        });
      });
    }
    
    return {
      achados,
      itensEncontrados: achados.length,
      metadados: {
        fonte: 'Ransomware.live',
        dominio,
        nomeEmpresa,
        totalVitimasVerificadas: vitimas.length,
        matchesEncontrados: vitimasEncontradas.length,
      },
    };
  } catch (erro: any) {
    console.error('Erro ao consultar Ransomware.live:', erro.message);
    throw erro;
  }
}

// Buscar grupos de ransomware ativos (para contexto)
export async function listarGruposRansomware(): Promise<{ nome: string; vitimas: number }[]> {
  try {
    const response = await axios.get<{ name: string; locations: any[] }[]>(
      `${RANSOMWARE_API}/groups`,
      { timeout: 30000 }
    );
    
    return response.data.map(g => ({
      nome: g.name,
      vitimas: g.locations?.length || 0,
    }));
  } catch {
    return [];
  }
}
