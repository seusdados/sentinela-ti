// ============================================================================
// SENTINELA - Middleware de Autenticação
// ============================================================================

import { Request, Response, NextFunction } from 'express';
import { verificarToken } from '../auth/jwt';
import { prisma } from '../config/prisma';
import { UsuarioAutenticado } from '../types';

declare global {
  namespace Express {
    interface Request {
      usuario?: UsuarioAutenticado;
    }
  }
}

export async function autenticar(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ erro: 'Token de autenticação não fornecido' });
      return;
    }
    
    const token = authHeader.substring(7);
    
    const payload = verificarToken(token);
    
    // Buscar membro para obter organização e perfil
    const membro = await prisma.membro.findFirst({
      where: {
        usuarioId: payload.sub,
        organizacaoId: payload.organizacaoId,
      },
      include: {
        usuario: true,
      },
    });
    
    if (!membro || !membro.usuario.ativo) {
      res.status(401).json({ erro: 'Usuário não encontrado ou inativo' });
      return;
    }
    
    req.usuario = {
      id: membro.usuarioId,
      email: membro.usuario.email,
      nome: membro.usuario.nome,
      organizacaoId: membro.organizacaoId,
      perfil: membro.perfil,
    };
    
    next();
  } catch (erro: any) {
    if (erro.name === 'TokenExpiredError') {
      res.status(401).json({ erro: 'Token expirado' });
      return;
    }
    
    res.status(401).json({ erro: 'Token inválido' });
  }
}

export function exigirPerfil(...perfisPermitidos: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.usuario) {
      res.status(401).json({ erro: 'Não autenticado' });
      return;
    }
    
    if (!perfisPermitidos.includes(req.usuario.perfil)) {
      res.status(403).json({ erro: 'Permissão negada para esta ação' });
      return;
    }
    
    next();
  };
}
