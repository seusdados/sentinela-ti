// ============================================================================
// Configuração do cliente de banco de dados
// Usa Supabase REST API quando conexão direta não está disponível
// ============================================================================

import { supabaseAdapter } from './supabaseAdapter';

// Exportar o adaptador Supabase como "prisma" para manter compatibilidade
export const prisma = supabaseAdapter;
