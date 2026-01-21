// ============================================================================
// SENTINELA - Página de Varreduras
// ============================================================================

import { useState, useEffect } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import {
  Radar,
  Search,
  Filter,
  CheckCircle,
  Clock,
  XCircle,
  AlertTriangle,
  Building2,
  Eye,
  Plus,
  Play,
} from 'lucide-react';
import { api } from '../services/api';

const STATUS_OPTIONS = [
  { value: '', label: 'Todos os status' },
  { value: 'AGUARDANDO', label: 'Aguardando' },
  { value: 'EXECUTANDO', label: 'Em execução' },
  { value: 'CONCLUIDA', label: 'Concluída' },
  { value: 'FALHOU', label: 'Falhou' },
];

function formatarData(data: string) {
  return new Date(data).toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function calcularDuracao(inicio?: string, fim?: string) {
  if (!inicio || !fim) return '-';
  const ms = new Date(fim).getTime() - new Date(inicio).getTime();
  const segundos = Math.floor(ms / 1000);
  const minutos = Math.floor(segundos / 60);
  if (minutos > 0) return `${minutos}min ${segundos % 60}s`;
  return `${segundos}s`;
}

export default function VarredurasPage() {
  const [searchParams] = useSearchParams();
  const [varreduras, setVarreduras] = useState<any[]>([]);
  const [empresas, setEmpresas] = useState<any[]>([]);
  const [carregando, setCarregando] = useState(true);
  const [status, setStatus] = useState(searchParams.get('status') || '');
  const [modalNovaVarredura, setModalNovaVarredura] = useState(false);
  
  useEffect(() => {
    carregarVarreduras();
    carregarEmpresas();
  }, [status]);
  
  const carregarEmpresas = async () => {
    try {
      const resposta = await api.getEmpresas({});
      setEmpresas(resposta.empresas || []);
    } catch (erro) {
      console.error('Erro ao carregar empresas:', erro);
    }
  };
  
  const carregarVarreduras = async () => {
    setCarregando(true);
    try {
      const resposta = await api.getVarreduras({ 
        status: status || undefined,
        empresaId: searchParams.get('empresaId') || undefined,
      });
      setVarreduras(resposta.varreduras || []);
    } catch (erro) {
      console.error('Erro ao carregar varreduras:', erro);
    } finally {
      setCarregando(false);
    }
  };
  
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'CONCLUIDA': return <CheckCircle className="w-4 h-4 text-green-600" />;
      case 'EXECUTANDO': return <Clock className="w-4 h-4 text-blue-600 animate-spin" />;
      case 'FALHOU': return <XCircle className="w-4 h-4 text-red-600" />;
      default: return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };
  
  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'CONCLUIDA': return 'Concluída';
      case 'EXECUTANDO': return 'Em execução';
      case 'FALHOU': return 'Falhou';
      case 'CANCELADA': return 'Cancelada';
      default: return 'Aguardando';
    }
  };
  
  return (
    <div className="space-y-6">
      {/* Cabeçalho */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Varreduras</h1>
          <p className="text-gray-500 mt-1">Histórico e status das varreduras de segurança</p>
        </div>
        <button onClick={() => setModalNovaVarredura(true)} className="btn btn-primary">
          <Plus className="w-4 h-4" />
          Nova Varredura
        </button>
      </div>
      
      {/* Filtros */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="input max-w-xs"
            >
              {STATUS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </div>
      </div>
      
      {/* Tabela */}
      <div className="card overflow-hidden">
        {carregando ? (
          <div className="p-8 text-center">
            <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
            <p className="text-gray-500 mt-2">Carregando varreduras...</p>
          </div>
        ) : varreduras.length === 0 ? (
          <div className="p-8 text-center">
            <Radar className="w-12 h-12 mx-auto text-gray-300 mb-4" />
            <p className="text-gray-500">Nenhuma varredura encontrada</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Empresa</th>
                  <th>Status</th>
                  <th>Achados</th>
                  <th>Duração</th>
                  <th>Criado por</th>
                  <th>Data</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {varreduras.map((v) => (
                  <tr key={v.id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-primary-100 flex items-center justify-center">
                          <Building2 className="w-4 h-4 text-primary-600" />
                        </div>
                        <div>
                          <Link to={`/empresas/${v.empresa.id}`} className="font-medium text-gray-900 hover:text-primary-600">
                            {v.empresa.nome}
                          </Link>
                          <p className="text-xs text-gray-500">ID: {v.id.slice(0, 8)}</p>
                        </div>
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(v.status)}
                        <span className={`badge ${
                          v.status === 'CONCLUIDA' ? 'badge-baixo' :
                          v.status === 'EXECUTANDO' ? 'badge-info' :
                          v.status === 'FALHOU' ? 'badge-critico' : 'status-aguardando'
                        }`}>
                          {getStatusLabel(v.status)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold">{v.totalAchados}</span>
                        {v.achadosCriticos > 0 && (
                          <span className="badge badge-critico text-[10px]">{v.achadosCriticos} críticos</span>
                        )}
                        {v.achadosAltos > 0 && (
                          <span className="badge badge-alto text-[10px]">{v.achadosAltos} altos</span>
                        )}
                      </div>
                    </td>
                    <td className="text-gray-500">
                      {calcularDuracao(v.iniciadaEm, v.concluidaEm)}
                    </td>
                    <td className="text-gray-500">{v.criadoPor || '-'}</td>
                    <td className="text-gray-500 text-sm">{formatarData(v.criadoEm)}</td>
                    <td>
                      <Link to={`/varreduras/${v.id}`} className="btn btn-ghost btn-sm">
                        <Eye className="w-4 h-4" />
                        Detalhes
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      
      {/* Modal Nova Varredura */}
      {modalNovaVarredura && (
        <ModalNovaVarredura
          empresas={empresas}
          onClose={() => setModalNovaVarredura(false)}
          onSuccess={() => {
            setModalNovaVarredura(false);
            carregarVarreduras();
          }}
        />
      )}
    </div>
  );
}

// Modal para iniciar nova varredura
function ModalNovaVarredura({ empresas, onClose, onSuccess }: { empresas: any[]; onClose: () => void; onSuccess: () => void }) {
  const navigate = useNavigate();
  const [empresaId, setEmpresaId] = useState('');
  const [escopo, setEscopo] = useState('COMPLETO');
  const [varreduraProfunda, setVarreduraProfunda] = useState(true);
  const [iniciando, setIniciando] = useState(false);
  const [erro, setErro] = useState('');
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!empresaId) {
      setErro('Selecione uma empresa');
      return;
    }
    
    setIniciando(true);
    setErro('');
    
    try {
      const resposta = await api.criarVarredura({
        empresaId,
        escopo,
        varreduraProfunda,
      });
      onSuccess();
      navigate(`/varreduras/${resposta.varredura.id}`);
    } catch (err: any) {
      setErro(err.message || 'Erro ao iniciar varredura');
      setIniciando(false);
    }
  };
  
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6 animate-slide-up">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-primary-100 flex items-center justify-center">
            <Radar className="w-5 h-5 text-primary-600" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-gray-900">Nova Varredura</h2>
            <p className="text-sm text-gray-500">Inicie uma varredura de segurança</p>
          </div>
        </div>
        
        {erro && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            {erro}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label">Empresa</label>
            <select
              value={empresaId}
              onChange={(e) => setEmpresaId(e.target.value)}
              className="input"
              required
            >
              <option value="">Selecione uma empresa...</option>
              {empresas.map((emp) => (
                <option key={emp.id} value={emp.id}>{emp.nome}</option>
              ))}
            </select>
          </div>
          
          <div>
            <label className="label">Escopo da Varredura</label>
            <select
              value={escopo}
              onChange={(e) => setEscopo(e.target.value)}
              className="input"
            >
              <option value="COMPLETO">Completo - Todas as fontes</option>
              <option value="RAPIDO">Rápido - Fontes principais</option>
              <option value="CUSTOMIZADO">Customizado - Selecionar fontes</option>
            </select>
          </div>
          
          <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
            <input
              type="checkbox"
              id="varreduraProfunda"
              checked={varreduraProfunda}
              onChange={(e) => setVarreduraProfunda(e.target.checked)}
              className="w-4 h-4 text-primary-600 rounded"
            />
            <label htmlFor="varreduraProfunda" className="flex-1">
              <span className="font-medium text-gray-900">Varredura Profunda</span>
              <p className="text-xs text-gray-500">Inclui análise de subdomínios e serviços expostos</p>
            </label>
          </div>
          
          <div className="flex gap-3 pt-4">
            <button type="button" onClick={onClose} className="btn btn-secondary flex-1">
              Cancelar
            </button>
            <button type="submit" disabled={iniciando} className="btn btn-primary flex-1">
              {iniciando ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                  Iniciando...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Iniciar Varredura
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
