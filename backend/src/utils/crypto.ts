// ============================================================================
// SENTINELA - Utilitários de Criptografia
// ============================================================================

import crypto from 'crypto';
import { env } from '../config/env';

const ALGORITMO = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

// Criptografa uma string usando AES-256-GCM
export function criptografar(texto: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const chave = Buffer.from(env.ENCRYPTION_KEY.slice(0, 32).padEnd(32, '0'));
  
  const cipher = crypto.createCipheriv(ALGORITMO, chave, iv);
  
  let encrypted = cipher.update(texto, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const tag = cipher.getAuthTag();
  
  // Formato: iv:tag:dados
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;
}

// Descriptografa uma string criptografada com AES-256-GCM
export function descriptografar(textoCriptografado: string): string {
  const partes = textoCriptografado.split(':');
  if (partes.length !== 3) {
    throw new Error('Formato de texto criptografado inválido');
  }
  
  const [ivHex, tagHex, dados] = partes;
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const chave = Buffer.from(env.ENCRYPTION_KEY.slice(0, 32).padEnd(32, '0'));
  
  const decipher = crypto.createDecipheriv(ALGORITMO, chave, iv);
  decipher.setAuthTag(tag);
  
  let decrypted = decipher.update(dados, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Gera hash SHA-256 de uma string
export function sha256Hex(texto: string): string {
  return crypto.createHash('sha256').update(texto).digest('hex');
}

// Cria impressão digital estável para deduplicação de achados
export function criarImpressaoDigital(dados: Record<string, any>): string {
  // Ordenar chaves para garantir consistência
  const chavesOrdenadas = Object.keys(dados).sort();
  const valoresOrdenados = chavesOrdenadas.map(k => `${k}:${dados[k]}`).join('|');
  
  return sha256Hex(valoresOrdenados);
}

// Gera um token aleatório seguro
export function gerarTokenSeguro(tamanho: number = 32): string {
  return crypto.randomBytes(tamanho).toString('hex');
}

// Compara strings de forma segura (tempo constante)
export function compararSeguro(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
