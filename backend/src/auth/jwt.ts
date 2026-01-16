// ============================================================================
// SENTINELA - Autenticação JWT
// ============================================================================

import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { TokenPayload } from '../types';

export function gerarTokenAcesso(payload: Omit<TokenPayload, 'iat' | 'exp'>): string {
  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN,
  });
}

export function gerarTokenRefresh(usuarioId: string): string {
  return jwt.sign(
    { sub: usuarioId, tipo: 'refresh' },
    env.JWT_SECRET,
    { expiresIn: env.REFRESH_TOKEN_EXPIRES_IN }
  );
}

export function verificarToken(token: string): TokenPayload {
  return jwt.verify(token, env.JWT_SECRET) as TokenPayload;
}

export function decodificarToken(token: string): TokenPayload | null {
  try {
    return jwt.decode(token) as TokenPayload;
  } catch {
    return null;
  }
}
