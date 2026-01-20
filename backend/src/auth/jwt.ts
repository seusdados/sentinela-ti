// ============================================================================
// SENTINELA - Autenticação JWT
// ============================================================================

import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { TokenPayload } from '../types';

// Converter string de tempo para segundos
function parseTimeToSeconds(time: string): number {
  const match = time.match(/^(\d+)([smhd])$/);
  if (!match) return 900; // default 15 minutos
  
  const value = parseInt(match[1], 10);
  const unit = match[2];
  
  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 60 * 60 * 24;
    default: return 900;
  }
}

export function gerarTokenAcesso(payload: Omit<TokenPayload, 'iat' | 'exp'>): string {
  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: parseTimeToSeconds(env.JWT_EXPIRES_IN),
  });
}

export function gerarTokenRefresh(usuarioId: string): string {
  return jwt.sign(
    { sub: usuarioId, tipo: 'refresh' },
    env.JWT_SECRET,
    { expiresIn: parseTimeToSeconds(env.REFRESH_TOKEN_EXPIRES_IN) }
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
