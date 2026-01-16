// ============================================================================
// SENTINELA - Página de Empresas
// ============================================================================

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Building2,
  Plus,
  Search,
  Globe,
  Shield,
  ShieldAlert,
  MoreVertical,
  Eye,
  Radar,
  ExternalLink,
} from 'lucide-react';
import { api } from '../services/api';

export default function EmpresasPage() {
  const [empresas, setEmpresas] = useState<any[]>([]);
  const [carregando, setCarregando] = useState(true);
  const [busca, setBusca] = useState('');
  const [modalAberto, setModalAberto] = useState(false);
  
  useEffect(() => {
    carregarEmpresas();
  }, []);
  
  const carregarEmpresas = async () => {
    try {
      const resposta = await api.getEmpresas({ busca });
      setEmpresas(resposta.empresas || []);
    } catch (erro) {
      console.error('Erro ao carregar empresas:', erro);
    } finally {
      setCarregando(false);
    }
  };
  
  const filtradas = empresas.filter(e => 
    !busca || 
    e.nome.toLowerCase().includes(busca.toLowerCase()) ||
    e.dominios?.some((d: string) => d.toLowerCase().includes(busca.toLowerCase()))
  );
  
  return (
    <div className="space-y-6">
      {/* Cabeçalho */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Empresas Monitoradas</h1>
          <p className="text-gray-500 mt-1">Gerencie as empresas sob vigilância de segurança</p>
        </div>
        <button onClick={() => setModalAberto(true)} className="btn btn-primary">
          <Plus className="w-4 h-4" />
          Cadastrar Empresa
        </button>
      </div>
      
      {/* Busca */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={busca}
              onChange={(e) => setBusca(e.target.value)}
              placeholder="Buscar por nome, domínio ou CNPJ..."
              className="input pl-10"
            />
          </div>
        </div>
      </div>
      
      {/* Lista de Empresas */}
      {carregando ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="card">
              <div className="skeleton h-6 w-3/4 mb-3"></div>
              <div className="skeleton h-4 w-1/2 mb-4"></div>
              <div className="skeleton h-4 w-full mb-2"></div>
              <div className="skeleton h-4 w-2/3"></div>
            </div>
          ))}
        </div>
      ) : filtradas.length === 0 ? (
        <div className="card text-center py-12">
          <Building2 className="w-12 h-12 mx-auto text-gray-300 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-1">Nenhuma empresa encontrada</h3>
          <p className="text-gray-500">
            {busca ? 'Tente outra busca ou' : 'Comece'} cadastrando uma nova empresa.
          </p>
          <button onClick={() => setModalAberto(true)} className="btn btn-primary mt-4">
            <Plus className="w-4 h-4" />
            Cadastrar Empresa
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filtradas.map((empresa) => (
            <div key={empresa.id} className="card hover:shadow-lg transition-shadow">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center">
                    <Building2 className="w-6 h-6 text-primary-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900">{empresa.nome}</h3>
                    {empresa.nomeFantasia && (
                      <p className="text-sm text-gray-500">{empresa.nomeFantasia}</p>
                    )}
                  </div>
                </div>
                <div className="flex items-center">
                  {empresa.monitorada ? (
                    <span className="badge badge-baixo">
                      <Shield className="w-3 h-3 mr-1" />
                      Monitorada
                    </span>
                  ) : (
                    <span className="badge bg-gray-100 text-gray-600">
                      Não monitorada
                    </span>
                  )}
                </div>
              </div>
              
              {/* Domínios */}
              <div className="mb-4">
                <p className="text-xs text-gray-500 uppercase font-medium mb-2">Domínios</p>
                <div className="flex flex-wrap gap-2">
                  {empresa.dominios?.slice(0, 3).map((dominio: string) => (
                    <span key={dominio} className="inline-flex items-center gap-1 px-2 py-1 bg-gray-100 rounded text-xs text-gray-700">
                      <Globe className="w-3 h-3" />
                      {dominio}
                    </span>
                  ))}
                  {empresa.dominios?.length > 3 && (
                    <span className="px-2 py-1 text-xs text-gray-500">
                      +{empresa.dominios.length - 3}
                    </span>
                  )}
                </div>
              </div>
              
              {/* Estatísticas */}
              <div className="flex items-center justify-between pt-4 border-t border-gray-100">
                <div className="text-sm text-gray-500">
                  <Radar className="w-4 h-4 inline mr-1" />
                  {empresa.totalVarreduras} varreduras
                </div>
                <Link
                  to={`/empresas/${empresa.id}`}
                  className="btn btn-ghost btn-sm"
                >
                  <Eye className="w-4 h-4" />
                  Detalhes
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
      
      {/* Modal de Cadastro (simplificado) */}
      {modalAberto && (
        <ModalCadastroEmpresa
          onClose={() => setModalAberto(false)}
          onSave={() => {
            setModalAberto(false);
            carregarEmpresas();
          }}
        />
      )}
    </div>
  );
}

// Modal de cadastro simplificado
function ModalCadastroEmpresa({ onClose, onSave }: { onClose: () => void; onSave: () => void }) {
  const [nome, setNome] = useState('');
  const [dominio, setDominio] = useState('');
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState('');
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSalvando(true);
    setErro('');
    
    try {
      await api.criarEmpresa({
        nome,
        dominios: [dominio.toLowerCase().trim()],
      });
      onSave();
    } catch (err: any) {
      setErro(err.message);
    } finally {
      setSalvando(false);
    }
  };
  
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6 animate-slide-up">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Cadastrar Nova Empresa</h2>
        
        {erro && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
            {erro}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label">Nome da empresa</label>
            <input
              type="text"
              value={nome}
              onChange={(e) => setNome(e.target.value)}
              className="input"
              placeholder="Ex: Empresa ABC Ltda"
              required
            />
          </div>
          
          <div>
            <label className="label">Domínio principal</label>
            <input
              type="text"
              value={dominio}
              onChange={(e) => setDominio(e.target.value)}
              className="input"
              placeholder="Ex: empresa.com.br"
              required
            />
            <p className="text-xs text-gray-500 mt-1">
              Informe o domínio principal. Você pode adicionar mais domínios depois.
            </p>
          </div>
          
          <div className="flex gap-3 pt-4">
            <button type="button" onClick={onClose} className="btn btn-secondary flex-1">
              Cancelar
            </button>
            <button type="submit" disabled={salvando} className="btn btn-primary flex-1">
              {salvando ? 'Salvando...' : 'Cadastrar'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
