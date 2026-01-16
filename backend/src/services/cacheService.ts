// ============================================================================
// SENTINELA - Serviço de Cache
// Armazena resultados de consultas para evitar requisições repetidas
// ============================================================================

import { prisma } from '../config/prisma';
import { FonteInformacao } from '@prisma/client';

export async function obterCache<T>(fonte: FonteInformacao, chave: string): Promise<T | null> {
  try {
    const registro = await prisma.cacheAmeaca.findUnique({
      where: { chave },
    });
    
    if (!registro) return null;
    
    // Verificar se expirou
    if (new Date() > registro.expiraEm) {
      // Remover cache expirado em background
      prisma.cacheAmeaca.delete({ where: { chave } }).catch(() => {});
      return null;
    }
    
    return registro.resposta as T;
  } catch {
    return null;
  }
}

export async function salvarCache<T>(
  fonte: FonteInformacao, 
  chave: string, 
  dados: T, 
  ttlMs: number
): Promise<void> {
  try {
    const expiraEm = new Date(Date.now() + ttlMs);
    
    await prisma.cacheAmeaca.upsert({
      where: { chave },
      create: {
        fonte,
        chave,
        resposta: dados as any,
        expiraEm,
      },
      update: {
        resposta: dados as any,
        expiraEm,
      },
    });
  } catch {
    // Ignorar erros de cache, não é crítico
  }
}

export async function limparCacheExpirado(): Promise<number> {
  const resultado = await prisma.cacheAmeaca.deleteMany({
    where: {
      expiraEm: { lt: new Date() },
    },
  });
  
  return resultado.count;
}

export async function limparCachePorFonte(fonte: FonteInformacao): Promise<number> {
  const resultado = await prisma.cacheAmeaca.deleteMany({
    where: { fonte },
  });
  
  return resultado.count;
}
