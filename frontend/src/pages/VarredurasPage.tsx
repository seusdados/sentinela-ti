// ============================================================================
// SENTINELA - Página de Varreduras
// ============================================================================

import { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
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
  const [carregando, setCarregando] = useState(true);
  const [status, setStatus] = useState(searchParams.get('status') || '');
  
  useEffect(() => {
    carregarVarreduras();
  }, [status]);
  
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
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Varreduras</h1>
        <p className="text-gray-500 mt-1">Histórico e status das varreduras de segurança</p>
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
    </div>
  );
}
