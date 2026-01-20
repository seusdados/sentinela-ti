// ============================================================================
// SENTINELA - Tipos e Interfaces TypeScript
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade, StatusExecucaoFonte } from '@prisma/client';

// ============================================================================
// RESULTADO DE FONTE DE INTELIGÊNCIA
// ============================================================================

export interface AchadoCandidato {
  fonte: FonteInformacao;
  nivelRisco: NivelRisco | 'CRITICO' | 'ALTO' | 'MEDIO' | 'BAIXO' | 'INFORMATIVO';
  tipo: string;
  tipoEntidade: TipoEntidade;
  entidade: string;
  titulo: string;
  descricao?: string;
  recomendacao?: string;
  evidencia?: Record<string, unknown>;
}

export interface ResultadoFonte {
  achados: AchadoCandidato[];
  itensEncontrados: number;
  metadados?: Record<string, unknown>;
}

export interface ResultadoExecucaoFonte {
  resultado?: ResultadoFonte;
  status: StatusExecucaoFonte;
  mensagemErro?: string;
  codigoErro?: string;
  codigoHttp?: number;
  duracaoMs: number;
  usouCache: boolean;
  limiteTaxa?: boolean;
}

// ============================================================================
// ESTATÍSTICAS E MÉTRICAS
// ============================================================================

export interface EstatisticasVarredura {
  totalAchados: number;
  porNivelRisco: {
    critico: number;
    alto: number;
    medio: number;
    baixo: number;
    informativo: number;
  };
  porFonte: Record<string, number>;
  porTipoEntidade: Record<string, number>;
  fontesExecutadas: number;
  fontesSucesso: number;
  fontesErro: number;
  duracaoTotalMs: number;
}

export interface ResumoDashboard {
  totalEmpresas: number;
  empresasMonitoradas: number;
  varredurasUltimos30Dias: number;
  totalAchados: number;
  achadosCriticos: number;
  achadosAltos: number;
  tendencia: {
    varreduras: number;
    achados: number;
  };
  ultimasVarreduras: {
    id: string;
    empresa: string;
    status: string;
    totalAchados: number;
    criadoEm: Date;
  }[];
  achadosRecentes: {
    id: string;
    titulo: string;
    nivelRisco: string;
    empresa: string;
    fonte: string;
    criadoEm: Date;
  }[];
  distribuicaoPorFonte: Record<string, number>;
  distribuicaoPorRisco: Record<string, number>;
}

// ============================================================================
// RELATÓRIO
// ============================================================================

export interface DadosRelatorio {
  varredura: {
    id: string;
    criadoEm: Date;
    iniciadaEm?: Date;
    concluidaEm?: Date;
    escopo: string;
  };
  empresa: {
    nome: string;
    cnpj?: string;
    dominios: string[];
  };
  estatisticas: EstatisticasVarredura;
  achados: {
    titulo: string;
    descricao?: string;
    recomendacao?: string;
    nivelRisco: string;
    fonte: string;
    tipoEntidade: string;
    entidade: string;
    evidencia?: Record<string, unknown>;
  }[];
  execucoesFonte: {
    fonte: string;
    status: string;
    itensEncontrados: number;
    duracaoMs: number;
    usouCache: boolean;
    mensagemErro?: string;
  }[];
}

// ============================================================================
// AUTENTICAÇÃO
// ============================================================================

export interface UsuarioAutenticado {
  id: string;
  email: string;
  nome: string;
  organizacaoId: string;
  perfil: string;
}

export interface TokenPayload {
  sub: string;
  email: string;
  organizacaoId: string;
  perfil: string;
  iat: number;
  exp: number;
}
