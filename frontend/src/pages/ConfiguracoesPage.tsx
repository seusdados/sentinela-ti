// ============================================================================
// SENTINELA - Página de Configurações
// Gerenciamento de chaves de API e configurações do sistema
// ============================================================================

import { useState, useEffect } from 'react';
import {
  Settings,
  Key,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  CheckCircle,
  XCircle,
  ExternalLink,
  AlertCircle,
  Shield,
} from 'lucide-react';
import { api } from '../services/api';

const PROVEDORES_INFO: Record<string, { nome: string; descricao: string; urlCadastro: string }> = {
  HIBP: {
    nome: 'Have I Been Pwned',
    descricao: 'Verificação de vazamentos de e-mail em bases de dados comprometidas. Essencial para detectar credenciais expostas.',
    urlCadastro: 'https://haveibeenpwned.com/API/Key',
  },
  VT: {
    nome: 'VirusTotal',
    descricao: 'Análise de reputação de domínios e URLs suspeitas. Verifica se seu domínio está marcado como malicioso.',
    urlCadastro: 'https://www.virustotal.com/gui/join-us',
  },
  LEAKIX: {
    nome: 'LeakIX',
    descricao: 'Detecção de vazamentos e configurações expostas na internet. Encontra bancos de dados abertos e arquivos sensíveis.',
    urlCadastro: 'https://leakix.net/auth/register',
  },
  SHODAN: {
    nome: 'Shodan',
    descricao: 'Descoberta de infraestrutura e serviços expostos na internet. Identifica servidores, portas e vulnerabilidades.',
    urlCadastro: 'https://account.shodan.io/register',
  },
  OTX: {
    nome: 'AlienVault OTX',
    descricao: 'Indicadores de ameaças compartilhados pela comunidade de segurança. Verifica se seu domínio está em listas de ameaças.',
    urlCadastro: 'https://otx.alienvault.com/accounts/signup/',
  },
  ABUSEIPDB: {
    nome: 'AbuseIPDB',
    descricao: 'Base de dados colaborativa de IPs maliciosos. Verifica a reputação dos IPs da sua infraestrutura.',
    urlCadastro: 'https://www.abuseipdb.com/register',
  },
  URLSCAN: {
    nome: 'URLScan.io',
    descricao: 'Análise de URLs e detecção de phishing. Identifica sites que tentam se passar pela sua empresa.',
    urlCadastro: 'https://urlscan.io/user/signup',
  },
  GITHUB: {
    nome: 'GitHub',
    descricao: 'Busca de secrets e credenciais em código público. Encontra senhas e chaves de API expostas em repositórios.',
    urlCadastro: 'https://github.com/settings/tokens',
  },
  INTELX: {
    nome: 'Intelligence X',
    descricao: 'Busca em vazamentos e arquivos históricos da internet. Acesso a dados de breaches indexados.',
    urlCadastro: 'https://intelx.io/signup',
  },
};

export default function ConfiguracoesPage() {
  const [provedores, setProvedores] = useState<any[]>([]);
  const [carregando, setCarregando] = useState(true);
  const [modalAberto, setModalAberto] = useState<string | null>(null);
  const [novaChave, setNovaChave] = useState('');
  const [mostrarChave, setMostrarChave] = useState<string | null>(null);
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState('');
  
  useEffect(() => {
    carregarChaves();
  }, []);
  
  const carregarChaves = async () => {
    try {
      const resposta = await api.getChavesApi();
      setProvedores(resposta.provedores || []);
    } catch (erro) {
      console.error('Erro ao carregar chaves:', erro);
    } finally {
      setCarregando(false);
    }
  };
  
  const salvarChave = async (provedor: string) => {
    if (!novaChave.trim()) {
      setErro('Digite a chave de API');
      return;
    }
    
    setSalvando(true);
    setErro('');
    
    try {
      await api.salvarChaveApi(provedor, novaChave);
      setModalAberto(null);
      setNovaChave('');
      carregarChaves();
    } catch (err: any) {
      setErro(err.message || 'Erro ao salvar chave');
    } finally {
      setSalvando(false);
    }
  };
  
  const removerChave = async (provedor: string) => {
    if (!confirm('Tem certeza que deseja remover esta chave de API?')) return;
    
    try {
      await api.removerChaveApi(provedor);
      carregarChaves();
    } catch (erro) {
      console.error('Erro ao remover chave:', erro);
    }
  };
  
  return (
    <div className="space-y-6">
      {/* Cabeçalho */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Configurações</h1>
        <p className="text-gray-500 mt-1">Gerencie as chaves de API e configurações da plataforma</p>
      </div>
      
      {/* Alerta informativo */}
      <div className="p-4 bg-blue-50 border border-blue-200 rounded-xl">
        <div className="flex gap-3">
          <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-medium text-blue-900">Por que configurar chaves de API?</h3>
            <p className="text-sm text-blue-700 mt-1">
              As chaves de API permitem que o Sentinela consulte diversas fontes de inteligência de ameaças. 
              Quanto mais fontes configuradas, mais completa será a análise de segurança das suas empresas.
              As chaves são armazenadas de forma criptografada e nunca são expostas.
            </p>
          </div>
        </div>
      </div>
      
      {/* Lista de Provedores */}
      {carregando ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="card">
              <div className="skeleton h-6 w-32 mb-2"></div>
              <div className="skeleton h-4 w-full mb-4"></div>
              <div className="skeleton h-10 w-full"></div>
            </div>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {provedores.map((prov) => {
            const info = PROVEDORES_INFO[prov.provedor] || { 
              nome: prov.provedor, 
              descricao: 'Fonte de inteligência de ameaças',
              urlCadastro: '' 
            };
            
            return (
              <div key={prov.provedor} className="card">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                      prov.configurada ? 'bg-green-100' : 'bg-gray-100'
                    }`}>
                      <Key className={`w-5 h-5 ${prov.configurada ? 'text-green-600' : 'text-gray-400'}`} />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900">{info.nome}</h3>
                      {prov.configurada ? (
                        <span className="text-xs text-green-600 flex items-center gap-1">
                          <CheckCircle className="w-3 h-3" />
                          Configurada
                        </span>
                      ) : (
                        <span className="text-xs text-gray-400 flex items-center gap-1">
                          <XCircle className="w-3 h-3" />
                          Não configurada
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                
                <p className="text-sm text-gray-500 mb-4">{info.descricao}</p>
                
                <div className="flex items-center gap-2">
                  {prov.configurada ? (
                    <>
                      <button
                        onClick={() => {
                          setModalAberto(prov.provedor);
                          setNovaChave('');
                          setErro('');
                        }}
                        className="btn btn-secondary btn-sm flex-1"
                      >
                        Atualizar Chave
                      </button>
                      <button
                        onClick={() => removerChave(prov.provedor)}
                        className="btn btn-ghost btn-sm text-red-600 hover:bg-red-50"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => {
                        setModalAberto(prov.provedor);
                        setNovaChave('');
                        setErro('');
                      }}
                      className="btn btn-primary btn-sm flex-1"
                    >
                      <Plus className="w-4 h-4" />
                      Adicionar Chave
                    </button>
                  )}
                  
                  {info.urlCadastro && (
                    <a
                      href={info.urlCadastro}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-ghost btn-sm"
                      title="Obter chave de API"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  )}
                </div>
                
                {prov.ultimoUsoEm && (
                  <p className="text-xs text-gray-400 mt-3">
                    Último uso: {new Date(prov.ultimoUsoEm).toLocaleDateString('pt-BR')}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
      
      {/* Modal de Configuração de Chave */}
      {modalAberto && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6 animate-slide-up">
            <h2 className="text-xl font-bold text-gray-900 mb-2">
              Configurar {PROVEDORES_INFO[modalAberto]?.nome || modalAberto}
            </h2>
            <p className="text-sm text-gray-500 mb-4">
              {PROVEDORES_INFO[modalAberto]?.descricao}
            </p>
            
            {erro && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
                <AlertCircle className="w-4 h-4" />
                {erro}
              </div>
            )}
            
            <div className="mb-4">
              <label className="label">Chave de API</label>
              <div className="relative">
                <input
                  type={mostrarChave === modalAberto ? 'text' : 'password'}
                  value={novaChave}
                  onChange={(e) => setNovaChave(e.target.value)}
                  className="input pr-12 font-mono"
                  placeholder="Cole sua chave de API aqui"
                />
                <button
                  type="button"
                  onClick={() => setMostrarChave(mostrarChave === modalAberto ? null : modalAberto)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {mostrarChave === modalAberto ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                A chave será armazenada de forma criptografada
              </p>
            </div>
            
            {PROVEDORES_INFO[modalAberto]?.urlCadastro && (
              <a
                href={PROVEDORES_INFO[modalAberto].urlCadastro}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-sm text-primary-600 hover:underline mb-4"
              >
                <ExternalLink className="w-4 h-4" />
                Obter chave de API gratuita
              </a>
            )}
            
            <div className="flex gap-3">
              <button
                onClick={() => {
                  setModalAberto(null);
                  setNovaChave('');
                  setErro('');
                }}
                className="btn btn-secondary flex-1"
              >
                Cancelar
              </button>
              <button
                onClick={() => salvarChave(modalAberto)}
                disabled={salvando}
                className="btn btn-primary flex-1"
              >
                {salvando ? 'Salvando...' : 'Salvar Chave'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
