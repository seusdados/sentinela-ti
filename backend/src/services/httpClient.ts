import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from 'axios';

// ============================================================================
// SENTINELA - Cliente HTTP com Tratamento Robusto de Erros
// ============================================================================

export interface RespostaHttp<T = any> {
  sucesso: boolean;
  dados?: T;
  erro?: {
    mensagem: string;
    codigo?: string;
    codigoHttp?: number;
    timeout?: boolean;
    limiteTaxa?: boolean;
  };
  duracaoMs: number;
}

class ClienteHttp {
  private cliente: AxiosInstance;

  constructor() {
    this.cliente = axios.create({
      timeout: 30000,
      headers: {
        'User-Agent': 'Sentinela-ThreatIntel/1.0 (+https://sentinela.app)',
        'Accept': 'application/json',
      },
    });

    // Interceptor para logging
    this.cliente.interceptors.request.use((config) => {
      (config as any)._iniciado = Date.now();
      return config;
    });
  }

  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<RespostaHttp<T>> {
    const inicio = Date.now();
    
    try {
      const resposta = await this.cliente.get<T>(url, config);
      
      return {
        sucesso: true,
        dados: resposta.data,
        duracaoMs: Date.now() - inicio,
      };
    } catch (erro) {
      return this.tratarErro<T>(erro, inicio);
    }
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<RespostaHttp<T>> {
    const inicio = Date.now();
    
    try {
      const resposta = await this.cliente.post<T>(url, data, config);
      
      return {
        sucesso: true,
        dados: resposta.data,
        duracaoMs: Date.now() - inicio,
      };
    } catch (erro) {
      return this.tratarErro<T>(erro, inicio);
    }
  }

  private tratarErro<T>(erro: unknown, inicio: number): RespostaHttp<T> {
    const duracaoMs = Date.now() - inicio;
    
    if (axios.isAxiosError(erro)) {
      const axiosErro = erro as AxiosError;
      
      // Timeout
      if (axiosErro.code === 'ECONNABORTED' || axiosErro.code === 'ETIMEDOUT') {
        return {
          sucesso: false,
          erro: {
            mensagem: 'A requisição excedeu o tempo limite de resposta',
            codigo: 'TIMEOUT',
            timeout: true,
          },
          duracaoMs,
        };
      }
      
      // Erro de rede
      if (axiosErro.code === 'ENOTFOUND' || axiosErro.code === 'ECONNREFUSED') {
        return {
          sucesso: false,
          erro: {
            mensagem: 'Não foi possível conectar ao servidor',
            codigo: 'NETWORK_ERROR',
          },
          duracaoMs,
        };
      }
      
      // Rate limit
      if (axiosErro.response?.status === 429) {
        return {
          sucesso: false,
          erro: {
            mensagem: 'Limite de requisições excedido. Tente novamente em alguns minutos.',
            codigo: 'RATE_LIMITED',
            codigoHttp: 429,
            limiteTaxa: true,
          },
          duracaoMs,
        };
      }
      
      // Não autorizado
      if (axiosErro.response?.status === 401 || axiosErro.response?.status === 403) {
        return {
          sucesso: false,
          erro: {
            mensagem: 'Chave de API inválida ou sem permissão',
            codigo: 'UNAUTHORIZED',
            codigoHttp: axiosErro.response.status,
          },
          duracaoMs,
        };
      }
      
      // Não encontrado (geralmente significa "sem resultados")
      if (axiosErro.response?.status === 404) {
        return {
          sucesso: true,
          dados: undefined,
          duracaoMs,
        };
      }
      
      // Outros erros HTTP
      if (axiosErro.response) {
        return {
          sucesso: false,
          erro: {
            mensagem: `Erro do servidor: ${axiosErro.response.statusText || 'Erro desconhecido'}`,
            codigo: 'HTTP_ERROR',
            codigoHttp: axiosErro.response.status,
          },
          duracaoMs,
        };
      }
    }
    
    // Erro genérico
    return {
      sucesso: false,
      erro: {
        mensagem: erro instanceof Error ? erro.message : 'Erro desconhecido',
        codigo: 'UNKNOWN_ERROR',
      },
      duracaoMs,
    };
  }
}

export const http = new ClienteHttp();
