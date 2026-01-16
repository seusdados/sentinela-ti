// ============================================================================
// SENTINELA - Serviço de Execução de Fontes
// Rastreia cada execução de fonte para auditoria forense
// ============================================================================

import { prisma } from '../config/prisma';
import { FonteInformacao, StatusExecucaoFonte } from '@prisma/client';

export interface IniciarExecucaoParams {
  varreduraId: string;
  fonte: FonteInformacao;
  consulta: string;
}

export async function iniciarExecucaoFonte(params: IniciarExecucaoParams) {
  const { varreduraId, fonte, consulta } = params;
  
  return prisma.execucaoFonte.create({
    data: {
      varreduraId,
      fonte,
      consulta,
      status: StatusExecucaoFonte.EXECUTANDO,
      iniciadaEm: new Date(),
    },
  });
}

export interface FinalizarExecucaoParams {
  status: StatusExecucaoFonte;
  codigoHttp?: number | null;
  duracaoMs?: number | null;
  itensEncontrados?: number | null;
  usouCache?: boolean;
  mensagemErro?: string | null;
  metadados?: any;
}

export async function finalizarExecucaoFonte(
  id: string, 
  params: FinalizarExecucaoParams
) {
  const { status, codigoHttp, duracaoMs, itensEncontrados, usouCache, mensagemErro, metadados } = params;
  
  return prisma.execucaoFonte.update({
    where: { id },
    data: {
      status,
      codigoHttp: codigoHttp ?? null,
      duracaoMs: duracaoMs ?? null,
      itensEncontrados: itensEncontrados ?? null,
      usouCache: usouCache ?? false,
      mensagemErro: mensagemErro ?? null,
      metadados: metadados ?? undefined,
      finalizadaEm: new Date(),
    },
  });
}

export async function marcarChaveAusente(id: string, mensagem?: string) {
  return finalizarExecucaoFonte(id, {
    status: StatusExecucaoFonte.CHAVE_AUSENTE,
    duracaoMs: 0,
    itensEncontrados: 0,
    mensagemErro: mensagem || 'Chave de API não configurada para esta fonte de inteligência',
  });
}

export async function marcarIgnorada(id: string, motivo: string) {
  return finalizarExecucaoFonte(id, {
    status: StatusExecucaoFonte.IGNORADA,
    duracaoMs: 0,
    itensEncontrados: 0,
    mensagemErro: motivo,
  });
}

export async function obterResumoExecucoes(varreduraId: string) {
  const execucoes = await prisma.execucaoFonte.findMany({
    where: { varreduraId },
    orderBy: { iniciadaEm: 'asc' },
  });
  
  const resumo = {
    total: execucoes.length,
    sucesso: 0,
    erro: 0,
    ignoradas: 0,
    chaveAusente: 0,
    cache: 0,
    duracaoTotalMs: 0,
    itensTotal: 0,
  };
  
  for (const exec of execucoes) {
    switch (exec.status) {
      case StatusExecucaoFonte.SUCESSO:
        resumo.sucesso++;
        break;
      case StatusExecucaoFonte.ERRO:
      case StatusExecucaoFonte.TIMEOUT:
      case StatusExecucaoFonte.LIMITE_TAXA:
        resumo.erro++;
        break;
      case StatusExecucaoFonte.IGNORADA:
        resumo.ignoradas++;
        break;
      case StatusExecucaoFonte.CHAVE_AUSENTE:
        resumo.chaveAusente++;
        break;
      case StatusExecucaoFonte.CACHE:
        resumo.cache++;
        resumo.sucesso++;
        break;
    }
    
    if (exec.duracaoMs) {
      resumo.duracaoTotalMs += exec.duracaoMs;
    }
    
    if (exec.itensEncontrados) {
      resumo.itensTotal += exec.itensEncontrados;
    }
  }
  
  return {
    resumo,
    execucoes: execucoes.map(e => ({
      id: e.id,
      fonte: e.fonte,
      consulta: e.consulta,
      status: e.status,
      codigoHttp: e.codigoHttp,
      duracaoMs: e.duracaoMs,
      itensEncontrados: e.itensEncontrados,
      usouCache: e.usouCache,
      mensagemErro: e.mensagemErro,
      iniciadaEm: e.iniciadaEm,
      finalizadaEm: e.finalizadaEm,
    })),
  };
}
