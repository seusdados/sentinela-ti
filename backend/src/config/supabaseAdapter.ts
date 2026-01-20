// ============================================================================
// Adaptador Supabase para substituir Prisma quando conexão direta não funciona
// ============================================================================

import { createClient, SupabaseClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL || 'https://exdmibuizlvhyczpqvio.supabase.co';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4ZG1pYnVpemx2aHljenBxdmlvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njg2MDA3MTcsImV4cCI6MjA4NDE3NjcxN30.wl4ZB6i6sm2CoyEFNAX6stfY3I1gHD5WNIGF_XhS_VQ';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Adaptador para manter compatibilidade com a interface do Prisma
export const supabaseAdapter = {
  usuario: {
    findUnique: async ({ where, include }: any) => {
      let query = supabase.from('usuarios').select('*');
      
      if (where.email) {
        query = query.eq('email', where.email);
      } else if (where.id) {
        query = query.eq('id', where.id);
      }
      
      const { data: usuario, error } = await query.single();
      
      if (error || !usuario) return null;
      
      // Mapear campos snake_case para camelCase
      const result: any = {
        id: usuario.id,
        email: usuario.email,
        nome: usuario.nome,
        senhaHash: usuario.senha_hash,
        ativo: usuario.ativo,
        ultimoAcessoEm: usuario.ultimo_acesso_em,
        avatarUrl: usuario.avatar_url,
        criadoEm: usuario.criado_em,
        atualizadoEm: usuario.atualizado_em,
      };
      
      // Incluir membros se solicitado
      if (include?.membros) {
        const { data: membros } = await supabase
          .from('membros')
          .select('*, organizacoes(*)')
          .eq('usuario_id', usuario.id)
          .limit(include.membros.take || 10);
        
        result.membros = (membros || []).map((m: any) => ({
          id: m.id,
          organizacaoId: m.organizacao_id,
          usuarioId: m.usuario_id,
          perfil: m.perfil,
          criadoEm: m.criado_em,
          organizacao: m.organizacoes ? {
            id: m.organizacoes.id,
            nome: m.organizacoes.nome,
            cnpj: m.organizacoes.cnpj,
            setor: m.organizacoes.setor,
            logotipoUrl: m.organizacoes.logotipo_url,
            corPrimaria: m.organizacoes.cor_primaria,
            criadoEm: m.organizacoes.criado_em,
            atualizadoEm: m.organizacoes.atualizado_em,
          } : null,
        }));
      }
      
      return result;
    },
    
    update: async ({ where, data }: any) => {
      const updateData: any = {};
      if (data.ultimoAcessoEm) updateData.ultimo_acesso_em = data.ultimoAcessoEm;
      if (data.nome) updateData.nome = data.nome;
      if (data.senhaHash) updateData.senha_hash = data.senhaHash;
      
      const { data: usuario, error } = await supabase
        .from('usuarios')
        .update(updateData)
        .eq('id', where.id)
        .select()
        .single();
      
      if (error) throw error;
      return usuario;
    },
  },
  
  tokenRefresh: {
    create: async ({ data }: any) => {
      const { data: token, error } = await supabase
        .from('tokens_refresh')
        .insert({
          usuario_id: data.usuarioId,
          token_hash: data.tokenHash,
          expira_em: data.expiraEm,
        })
        .select()
        .single();
      
      if (error) throw error;
      return token;
    },
    
    findFirst: async ({ where }: any) => {
      const { data: token, error } = await supabase
        .from('tokens_refresh')
        .select('*')
        .eq('token_hash', where.tokenHash)
        .eq('revogado', false)
        .gt('expira_em', new Date().toISOString())
        .single();
      
      if (error || !token) return null;
      return {
        id: token.id,
        usuarioId: token.usuario_id,
        tokenHash: token.token_hash,
        expiraEm: token.expira_em,
        revogado: token.revogado,
        criadoEm: token.criado_em,
      };
    },
    
    update: async ({ where, data }: any) => {
      const { error } = await supabase
        .from('tokens_refresh')
        .update({ revogado: data.revogado })
        .eq('id', where.id);
      
      if (error) throw error;
    },
  },
  
  empresa: {
    count: async ({ where }: any = {}) => {
      let query = supabase.from('empresas').select('id', { count: 'exact', head: true });
      
      if (where?.organizacaoId) query = query.eq('organizacao_id', where.organizacaoId);
      if (where?.ativa !== undefined) query = query.eq('ativa', where.ativa);
      
      const { count, error } = await query;
      if (error) throw error;
      return count || 0;
    },
    
    findMany: async ({ where, include, orderBy, skip, take }: any = {}) => {
      let query = supabase.from('empresas').select('*');
      
      if (where?.organizacaoId) query = query.eq('organizacao_id', where.organizacaoId);
      if (where?.ativa !== undefined) query = query.eq('ativa', where.ativa);
      
      if (orderBy) {
        const [field, order] = Object.entries(orderBy)[0] as [string, string];
        query = query.order(field === 'nome' ? 'nome' : field, { ascending: order === 'asc' });
      }
      
      if (skip) query = query.range(skip, skip + (take || 20) - 1);
      else if (take) query = query.limit(take);
      
      const { data: empresas, error } = await query;
      if (error) throw error;
      
      return (empresas || []).map((e: any) => ({
        id: e.id,
        organizacaoId: e.organizacao_id,
        nome: e.nome,
        nomeFantasia: e.nome_fantasia,
        cnpj: e.cnpj,
        setor: e.setor,
        emailPrincipal: e.email_principal,
        ativa: e.ativa,
        criadoEm: e.criado_em,
        atualizadoEm: e.atualizado_em,
        dominios: [],
        monitoramento: null,
        _count: { varreduras: 0 },
      }));
    },
    
    findFirst: async ({ where, include }: any) => {
      let query = supabase.from('empresas').select('*');
      
      if (where?.id) query = query.eq('id', where.id);
      if (where?.organizacaoId) query = query.eq('organizacao_id', where.organizacaoId);
      
      const { data: empresa, error } = await query.single();
      if (error || !empresa) return null;
      
      return {
        id: empresa.id,
        organizacaoId: empresa.organizacao_id,
        nome: empresa.nome,
        nomeFantasia: empresa.nome_fantasia,
        cnpj: empresa.cnpj,
        setor: empresa.setor,
        emailPrincipal: empresa.email_principal,
        ativa: empresa.ativa,
        criadoEm: empresa.criado_em,
        atualizadoEm: empresa.atualizado_em,
      };
    },
    
    create: async ({ data, include }: any) => {
      const { data: empresa, error } = await supabase
        .from('empresas')
        .insert({
          organizacao_id: data.organizacaoId,
          nome: data.nome,
          nome_fantasia: data.nomeFantasia,
          cnpj: data.cnpj,
          setor: data.setor,
          email_principal: data.emailPrincipal,
          criado_por_id: data.criadoPorId,
        })
        .select()
        .single();
      
      if (error) throw error;
      
      // Criar domínios
      if (data.dominios?.create) {
        for (const d of data.dominios.create) {
          await supabase.from('dominios_empresa').insert({
            empresa_id: empresa.id,
            dominio: d.dominio,
            principal: d.principal,
          });
        }
      }
      
      return {
        id: empresa.id,
        nome: empresa.nome,
        dominios: data.dominios?.create || [],
      };
    },
  },
  
  monitoramentoEmpresa: {
    count: async ({ where }: any = {}) => {
      let query = supabase.from('monitoramento_empresas').select('id', { count: 'exact', head: true });
      
      if (where?.ativo !== undefined) query = query.eq('ativo', where.ativo);
      
      const { count, error } = await query;
      if (error) throw error;
      return count || 0;
    },
  },
  
  varredura: {
    count: async ({ where }: any = {}) => {
      let query = supabase.from('varreduras').select('id', { count: 'exact', head: true });
      
      if (where?.criadoEm?.gte) {
        query = query.gte('criado_em', where.criadoEm.gte.toISOString());
      }
      
      const { count, error } = await query;
      if (error) throw error;
      return count || 0;
    },
    
    findMany: async ({ where, orderBy, take, include }: any = {}) => {
      let query = supabase.from('varreduras').select('*, empresas(nome)');
      
      if (orderBy?.criadoEm) {
        query = query.order('criado_em', { ascending: orderBy.criadoEm === 'asc' });
      }
      
      if (take) query = query.limit(take);
      
      const { data: varreduras, error } = await query;
      if (error) throw error;
      
      return (varreduras || []).map((v: any) => ({
        id: v.id,
        empresaId: v.empresa_id,
        status: v.status,
        totalAchados: v.total_achados,
        achadosCriticos: v.achados_criticos,
        achadosAltos: v.achados_altos,
        achadosMedios: v.achados_medios,
        achadosBaixos: v.achados_baixos,
        criadoEm: v.criado_em,
        empresa: v.empresas ? { nome: v.empresas.nome } : { nome: 'N/A' },
      }));
    },
  },
  
  definicaoAchado: {
    count: async ({ where }: any = {}) => {
      let query = supabase.from('definicoes_achado').select('id', { count: 'exact', head: true });
      
      if (where?.organizacaoId) query = query.eq('organizacao_id', where.organizacaoId);
      if (where?.nivelRisco) query = query.eq('nivel_risco', where.nivelRisco);
      if (where?.status) query = query.eq('status', where.status);
      
      const { count, error } = await query;
      if (error) throw error;
      return count || 0;
    },
    
    findMany: async ({ where, orderBy, take, include }: any = {}) => {
      let query = supabase.from('definicoes_achado').select('*');
      
      if (where?.organizacaoId) query = query.eq('organizacao_id', where.organizacaoId);
      
      if (orderBy?.ultimaVezEm) {
        query = query.order('ultima_vez_em', { ascending: orderBy.ultimaVezEm === 'asc' });
      }
      
      if (take) query = query.limit(take);
      
      const { data: achados, error } = await query;
      if (error) throw error;
      
      return (achados || []).map((a: any) => ({
        id: a.id,
        titulo: a.titulo,
        descricao: a.descricao,
        nivelRisco: a.nivel_risco,
        fonte: a.fonte,
        tipo: a.tipo,
        tipoEntidade: a.tipo_entidade,
        entidade: a.entidade,
        status: a.status,
        ultimaVezEm: a.ultima_vez_em,
        primeiraVezEm: a.primeira_vez_em,
        ocorrencias: [],
      }));
    },
    
    groupBy: async ({ by, where, _count }: any) => {
      // Simplificado - retorna array vazio por enquanto
      return [];
    },
  },
  
  chaveApi: {
    findMany: async ({ where }: any = {}) => {
      let query = supabase.from('chaves_api').select('*');
      
      if (where?.organizacaoId) query = query.eq('organizacao_id', where.organizacaoId);
      
      const { data: chaves, error } = await query;
      if (error) throw error;
      
      return (chaves || []).map((c: any) => ({
        id: c.id,
        organizacaoId: c.organizacao_id,
        provedor: c.provedor,
        segredoCriptografado: c.segredo_criptografado,
        ativa: c.ativa,
        ultimoUsoEm: c.ultimo_uso_em,
        criadoEm: c.criado_em,
        atualizadoEm: c.atualizado_em,
        criadoPorId: c.criado_por_id,
      }));
    },
    
    findFirst: async ({ where }: any) => {
      let query = supabase.from('chaves_api').select('*');
      
      if (where?.organizacaoId) query = query.eq('organizacao_id', where.organizacaoId);
      if (where?.provedor) query = query.eq('provedor', where.provedor);
      if (where?.ativa !== undefined) query = query.eq('ativa', where.ativa);
      
      const { data: chave, error } = await query.single();
      if (error || !chave) return null;
      
      return {
        id: chave.id,
        organizacaoId: chave.organizacao_id,
        provedor: chave.provedor,
        segredoCriptografado: chave.segredo_criptografado,
        ativa: chave.ativa,
        ultimoUsoEm: chave.ultimo_uso_em,
        criadoEm: chave.criado_em,
        atualizadoEm: chave.atualizado_em,
        criadoPorId: chave.criado_por_id,
      };
    },
    
    upsert: async ({ where, create, update }: any) => {
      // Verificar se existe
      const existing = await supabaseAdapter.chaveApi.findFirst({ where });
      
      if (existing) {
        const { data, error } = await supabase
          .from('chaves_api')
          .update({
            segredo_criptografado: update.segredoCriptografado,
            ativa: update.ativa,
            atualizado_em: new Date().toISOString(),
          })
          .eq('id', existing.id)
          .select()
          .single();
        
        if (error) throw error;
        return data;
      } else {
        const { data, error } = await supabase
          .from('chaves_api')
          .insert({
            organizacao_id: create.organizacaoId,
            provedor: create.provedor,
            segredo_criptografado: create.segredoCriptografado,
            ativa: create.ativa,
            criado_por_id: create.criadoPorId,
          })
          .select()
          .single();
        
        if (error) throw error;
        return data;
      }
    },
    
    delete: async ({ where }: any) => {
      const { error } = await supabase
        .from('chaves_api')
        .delete()
        .eq('id', where.id);
      
      if (error) throw error;
    },
  },
  
  organizacao: {
    findFirst: async ({ where }: any) => {
      let query = supabase.from('organizacoes').select('*');
      
      if (where?.id) query = query.eq('id', where.id);
      
      const { data: org, error } = await query.single();
      if (error || !org) return null;
      
      return {
        id: org.id,
        nome: org.nome,
        cnpj: org.cnpj,
        setor: org.setor,
        logotipoUrl: org.logotipo_url,
        corPrimaria: org.cor_primaria,
        criadoEm: org.criado_em,
        atualizadoEm: org.atualizado_em,
      };
    },
  },
};

export default supabaseAdapter;
