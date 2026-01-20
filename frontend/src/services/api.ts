// ============================================================================
// SENTINELA - Serviço de API
// ============================================================================

const API_BASE = '/api';

interface RequestConfig {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: any;
  headers?: Record<string, string>;
}

class ApiService {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem('sentinela_token', token);
    } else {
      localStorage.removeItem('sentinela_token');
    }
  }

  getToken(): string | null {
    if (!this.token) {
      this.token = localStorage.getItem('sentinela_token');
    }
    return this.token;
  }

  async request<T>(endpoint: string, config: RequestConfig = {}): Promise<T> {
    const { method = 'GET', body, headers = {} } = config;

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    if (body && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (response.status === 401) {
      this.setToken(null);
      window.location.href = '/login';
      throw new Error('Sessão expirada');
    }

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.erro || 'Erro na requisição');
    }

    return data;
  }

  // Auth
  async login(email: string, senha: string) {
    const data = await this.request<{
      tokenAcesso: string;
      tokenRefresh: string;
      usuario: any;
    }>('/auth/login', {
      method: 'POST',
      body: { email, senha },
    });
    
    this.setToken(data.tokenAcesso);
    localStorage.setItem('sentinela_refresh', data.tokenRefresh);
    localStorage.setItem('sentinela_usuario', JSON.stringify(data.usuario));
    
    return data;
  }

  logout() {
    this.setToken(null);
    localStorage.removeItem('sentinela_refresh');
    localStorage.removeItem('sentinela_usuario');
  }

  getUsuarioLogado() {
    const str = localStorage.getItem('sentinela_usuario');
    return str ? JSON.parse(str) : null;
  }

  // Dashboard
  getDashboard() {
    return this.request<any>('/dashboard');
  }

  // Empresas
  getEmpresas(params?: { busca?: string; pagina?: number }) {
    const query = new URLSearchParams();
    if (params?.busca) query.set('busca', params.busca);
    if (params?.pagina) query.set('pagina', String(params.pagina));
    return this.request<any>(`/empresas?${query}`);
  }

  getEmpresa(id: string) {
    return this.request<any>(`/empresas/${id}`);
  }

  criarEmpresa(dados: any) {
    return this.request<any>('/empresas', { method: 'POST', body: dados });
  }

  // Varreduras
  getVarreduras(params?: { empresaId?: string; status?: string; pagina?: number }) {
    const query = new URLSearchParams();
    if (params?.empresaId) query.set('empresaId', params.empresaId);
    if (params?.status) query.set('status', params.status);
    if (params?.pagina) query.set('pagina', String(params.pagina));
    return this.request<any>(`/varreduras?${query}`);
  }

  getVarredura(id: string) {
    return this.request<any>(`/varreduras/${id}`);
  }

  criarVarredura(dados: any) {
    return this.request<any>('/varreduras', { method: 'POST', body: dados });
  }

  // Configurações
  getChavesApi() {
    return this.request<any>('/chaves-api');
  }

  salvarChaveApi(provedor: string, chave: string) {
    return this.request<any>(`/chaves-api/${provedor}`, {
      method: 'POST',
      body: { chave },
    });
  }

  removerChaveApi(provedor: string) {
    return this.request<any>(`/chaves-api/${provedor}`, {
      method: 'DELETE',
    });
  }

  // Usuários
  getUsuarios() {
    return this.request<any>('/usuarios');
  }

  criarUsuario(dados: any) {
    return this.request<any>('/usuarios', { method: 'POST', body: dados });
  }
}

export const api = new ApiService();
