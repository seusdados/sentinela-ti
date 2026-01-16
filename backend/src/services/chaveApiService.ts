// ============================================================================
// SENTINELA - Serviço de Chaves de API
// Gerencia chaves de API criptografadas para fontes externas
// ============================================================================

import { prisma } from '../config/prisma';
import { ProvedorApi } from '@prisma/client';
import { criptografar, descriptografar } from '../utils/crypto';

export async function obterChaveApi(
  organizacaoId: string, 
  provedor: string
): Promise<string | null> {
  try {
    const provedorEnum = provedor as ProvedorApi;
    
    const chave = await prisma.chaveApi.findUnique({
      where: {
        organizacaoId_provedor: {
          organizacaoId,
          provedor: provedorEnum,
        },
      },
    });
    
    if (!chave || !chave.ativa) return null;
    
    // Atualizar último uso
    prisma.chaveApi.update({
      where: { id: chave.id },
      data: { ultimoUsoEm: new Date() },
    }).catch(() => {});
    
    return descriptografar(chave.segredoCriptografado);
  } catch {
    return null;
  }
}

export async function salvarChaveApi(params: {
  organizacaoId: string;
  provedor: ProvedorApi;
  segredo: string;
  usuarioId?: string;
}): Promise<void> {
  const { organizacaoId, provedor, segredo, usuarioId } = params;
  
  const segredoCriptografado = criptografar(segredo);
  
  await prisma.chaveApi.upsert({
    where: {
      organizacaoId_provedor: { organizacaoId, provedor },
    },
    create: {
      organizacaoId,
      provedor,
      segredoCriptografado,
      criadoPorId: usuarioId,
    },
    update: {
      segredoCriptografado,
      ativa: true,
      atualizadoEm: new Date(),
    },
  });
}

export async function removerChaveApi(
  organizacaoId: string, 
  provedor: ProvedorApi
): Promise<void> {
  await prisma.chaveApi.deleteMany({
    where: { organizacaoId, provedor },
  });
}

export async function listarChavesApi(organizacaoId: string) {
  const chaves = await prisma.chaveApi.findMany({
    where: { organizacaoId },
    select: {
      id: true,
      provedor: true,
      ativa: true,
      ultimoUsoEm: true,
      criadoEm: true,
      criadoPor: {
        select: { nome: true, email: true },
      },
    },
    orderBy: { provedor: 'asc' },
  });
  
  return chaves;
}

// Mapeamento de provedores para nomes legíveis
export const PROVEDORES_INFO: Record<ProvedorApi, { nome: string; descricao: string; urlCadastro: string }> = {
  [ProvedorApi.HIBP]: {
    nome: 'Have I Been Pwned',
    descricao: 'Verificação de vazamentos de e-mail em bases de dados comprometidas',
    urlCadastro: 'https://haveibeenpwned.com/API/Key',
  },
  [ProvedorApi.VT]: {
    nome: 'VirusTotal',
    descricao: 'Análise de reputação de domínios e URLs suspeitas',
    urlCadastro: 'https://www.virustotal.com/gui/join-us',
  },
  [ProvedorApi.LEAKIX]: {
    nome: 'LeakIX',
    descricao: 'Detecção de vazamentos e configurações expostas',
    urlCadastro: 'https://leakix.net/auth/register',
  },
  [ProvedorApi.SHODAN]: {
    nome: 'Shodan',
    descricao: 'Descoberta de infraestrutura e serviços expostos na internet',
    urlCadastro: 'https://account.shodan.io/register',
  },
  [ProvedorApi.OTX]: {
    nome: 'AlienVault OTX',
    descricao: 'Indicadores de ameaças compartilhados pela comunidade de segurança',
    urlCadastro: 'https://otx.alienvault.com/accounts/signup/',
  },
  [ProvedorApi.ABUSEIPDB]: {
    nome: 'AbuseIPDB',
    descricao: 'Base de dados colaborativa de IPs maliciosos',
    urlCadastro: 'https://www.abuseipdb.com/register',
  },
  [ProvedorApi.URLSCAN]: {
    nome: 'URLScan.io',
    descricao: 'Análise de URLs e detecção de phishing',
    urlCadastro: 'https://urlscan.io/user/signup',
  },
  [ProvedorApi.PSBDMP]: {
    nome: 'PSBDMP',
    descricao: 'Busca em pastes e dumps públicos (não requer chave)',
    urlCadastro: '',
  },
  [ProvedorApi.GITHUB]: {
    nome: 'GitHub',
    descricao: 'Busca de secrets e credenciais em código público',
    urlCadastro: 'https://github.com/settings/tokens',
  },
  [ProvedorApi.INTELX]: {
    nome: 'Intelligence X',
    descricao: 'Busca em vazamentos e arquivos históricos da internet',
    urlCadastro: 'https://intelx.io/signup',
  },
};
