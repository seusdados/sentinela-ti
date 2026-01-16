// ============================================================================
// SENTINELA - Página de Detalhe da Varredura
// Visualização completa dos achados e execuções
// ============================================================================

import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Building2,
  CheckCircle,
  Clock,
  XCircle,
  AlertTriangle,
  Shield,
  FileText,
  Download,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Server,
  Globe,
  Mail,
  Code,
  Database,
} from 'lucide-react';
import { api } from '../services/api';

const NOMES_RISCO = {
  CRITICO: 'Crítico',
  ALTO: 'Alto',
  MEDIO: 'Médio',
  BAIXO: 'Baixo',
  INFORMATIVO: 'Informativo',
};

const CORES_RISCO = {
  CRITICO: 'badge-critico',
  ALTO: 'badge-alto',
  MEDIO: 'badge-medio',
  BAIXO: 'badge-baixo',
  INFORMATIVO: 'badge-info',
};

const ICONES_ENTIDADE: Record<string, any> = {
  DOMINIO: Globe,
  SUBDOMINIO: Globe,
  IP: Server,
  EMAIL: Mail,
  URL: ExternalLink,
  CODIGO: Code,
  TEXTO: FileText,
  CREDENCIAL: Database,
};

function formatarData(data: string) {
  return new Date(data).toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function VarreduraDetalhePage() {
  const { id } = useParams();
  const [dados, setDados] = useState<any>(null);
  const [carregando, setCarregando] = useState(true);
  const [abaAtiva, setAbaAtiva] = useState<'achados' | 'fontes'>('achados');
  const [filtroRisco, setFiltroRisco] = useState<string>('');
  const [achadoExpandido, setAchadoExpandido] = useState<string | null>(null);
  
  useEffect(() => {
    carregarDados();
    
    // Atualizar a cada 5 segundos se estiver em execução
    const intervalo = setInterval(() => {
      if (dados?.varredura?.status === 'EXECUTANDO') {
        carregarDados();
      }
    }, 5000);
    
    return () => clearInterval(intervalo);
  }, [id]);
  
  const carregarDados = async () => {
    try {
      const resposta = await api.getVarredura(id!);
      setDados(resposta);
    } catch (erro) {
      console.error('Erro ao carregar varredura:', erro);
    } finally {
      setCarregando(false);
    }
  };
  
  if (carregando) {
    return (
      <div className="space-y-6">
        <div className="skeleton h-8 w-48"></div>
        <div className="card">
          <div className="skeleton h-6 w-64 mb-4"></div>
          <div className="skeleton h-4 w-full mb-2"></div>
          <div className="skeleton h-4 w-3/4"></div>
        </div>
      </div>
    );
  }
  
  if (!dados) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Varredura não encontrada</p>
        <Link to="/varreduras" className="btn btn-primary mt-4">
          Voltar para lista
        </Link>
      </div>
    );
  }
  
  const { varredura, achados, execucoesFonte, resumoExecucoes } = dados;
  
  const achadosFiltrados = achados?.filter((a: any) => 
    !filtroRisco || a.nivelRisco === filtroRisco
  ) || [];
  
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'CONCLUIDA': return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'EXECUTANDO': return <RefreshCw className="w-5 h-5 text-blue-600 animate-spin" />;
      case 'FALHOU': return <XCircle className="w-5 h-5 text-red-600" />;
      default: return <Clock className="w-5 h-5 text-gray-400" />;
    }
  };
  
  return (
    <div className="space-y-6">
      {/* Navegação */}
      <Link to="/varreduras" className="inline-flex items-center gap-2 text-gray-500 hover:text-gray-700">
        <ArrowLeft className="w-4 h-4" />
        Voltar para varreduras
      </Link>
      
      {/* Cabeçalho */}
      <div className="card">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-primary-100 flex items-center justify-center">
              {getStatusIcon(varredura.status)}
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl font-bold text-gray-900">
                  Varredura #{varredura.id.slice(0, 8)}
                </h1>
                <span className={`badge ${
                  varredura.status === 'CONCLUIDA' ? 'badge-baixo' :
                  varredura.status === 'EXECUTANDO' ? 'badge-info' :
                  varredura.status === 'FALHOU' ? 'badge-critico' : 'status-aguardando'
                }`}>
                  {varredura.status === 'CONCLUIDA' ? 'Concluída' :
                   varredura.status === 'EXECUTANDO' ? 'Em execução' :
                   varredura.status === 'FALHOU' ? 'Falhou' : 'Aguardando'}
                </span>
              </div>
              <div className="flex items-center gap-4 mt-1 text-sm text-gray-500">
                <Link to={`/empresas/${varredura.empresa.id}`} className="flex items-center gap-1 hover:text-primary-600">
                  <Building2 className="w-4 h-4" />
                  {varredura.empresa.nome}
                </Link>
                <span>•</span>
                <span>{formatarData(varredura.criadoEm)}</span>
              </div>
            </div>
          </div>
          
          {varredura.relatorio && (
            <a
              href={`/api/varreduras/${varredura.id}/relatorio`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary"
            >
              <Download className="w-4 h-4" />
              Baixar Relatório PDF
            </a>
          )}
        </div>
        
        {/* Métricas */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-6 border-t border-gray-100">
          <div>
            <p className="text-sm text-gray-500">Total de Achados</p>
            <p className="text-2xl font-bold text-gray-900">{varredura.totalAchados}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Críticos</p>
            <p className="text-2xl font-bold text-red-600">{varredura.achadosCriticos}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Altos</p>
            <p className="text-2xl font-bold text-orange-600">{varredura.achadosAltos}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Médios</p>
            <p className="text-2xl font-bold text-amber-600">{varredura.achadosMedios}</p>
          </div>
        </div>
        
        {varredura.mensagemErro && (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex items-center gap-2 text-red-700 font-medium mb-1">
              <AlertTriangle className="w-4 h-4" />
              Erro na varredura
            </div>
            <p className="text-sm text-red-600">{varredura.mensagemErro}</p>
          </div>
        )}
      </div>
      
      {/* Abas */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-6">
          <button
            onClick={() => setAbaAtiva('achados')}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
              abaAtiva === 'achados'
                ? 'border-primary-500 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Achados ({achados?.length || 0})
          </button>
          <button
            onClick={() => setAbaAtiva('fontes')}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
              abaAtiva === 'fontes'
                ? 'border-primary-500 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Execuções por Fonte ({execucoesFonte?.length || 0})
          </button>
        </nav>
      </div>
      
      {/* Conteúdo das Abas */}
      {abaAtiva === 'achados' && (
        <div className="space-y-4">
          {/* Filtros */}
          <div className="flex gap-2 flex-wrap">
            <button
              onClick={() => setFiltroRisco('')}
              className={`btn btn-sm ${!filtroRisco ? 'btn-primary' : 'btn-secondary'}`}
            >
              Todos
            </button>
            {['CRITICO', 'ALTO', 'MEDIO', 'BAIXO'].map((nivel) => (
              <button
                key={nivel}
                onClick={() => setFiltroRisco(nivel)}
                className={`btn btn-sm ${filtroRisco === nivel ? 'btn-primary' : 'btn-secondary'}`}
              >
                {NOMES_RISCO[nivel as keyof typeof NOMES_RISCO]}
              </button>
            ))}
          </div>
          
          {/* Lista de Achados */}
          {achadosFiltrados.length === 0 ? (
            <div className="card text-center py-12">
              <Shield className="w-12 h-12 mx-auto text-gray-300 mb-4" />
              <p className="text-gray-500">
                {filtroRisco ? 'Nenhum achado com este nível de risco' : 'Nenhum achado encontrado'}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {achadosFiltrados.map((achado: any) => {
                const IconeEntidade = ICONES_ENTIDADE[achado.tipoEntidade] || FileText;
                const expandido = achadoExpandido === achado.id;
                
                return (
                  <div key={achado.id} className="card">
                    <button
                      onClick={() => setAchadoExpandido(expandido ? null : achado.id)}
                      className="w-full text-left"
                    >
                      <div className="flex items-start gap-4">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                          achado.nivelRisco === 'CRITICO' ? 'bg-red-100' :
                          achado.nivelRisco === 'ALTO' ? 'bg-orange-100' :
                          achado.nivelRisco === 'MEDIO' ? 'bg-amber-100' :
                          'bg-green-100'
                        }`}>
                          <IconeEntidade className={`w-5 h-5 ${
                            achado.nivelRisco === 'CRITICO' ? 'text-red-600' :
                            achado.nivelRisco === 'ALTO' ? 'text-orange-600' :
                            achado.nivelRisco === 'MEDIO' ? 'text-amber-600' :
                            'text-green-600'
                          }`} />
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`badge ${CORES_RISCO[achado.nivelRisco as keyof typeof CORES_RISCO]}`}>
                              {NOMES_RISCO[achado.nivelRisco as keyof typeof NOMES_RISCO]}
                            </span>
                            <span className="badge bg-gray-100 text-gray-700">{achado.fonte}</span>
                          </div>
                          <h3 className="font-semibold text-gray-900 mt-2">{achado.titulo}</h3>
                          <p className="text-sm text-gray-500 mt-1 line-clamp-2">{achado.descricao}</p>
                          <div className="flex items-center gap-2 mt-2 text-xs text-gray-400">
                            <span className="font-mono bg-gray-100 px-2 py-0.5 rounded">
                              {achado.entidade}
                            </span>
                          </div>
                        </div>
                        
                        <div className="flex-shrink-0">
                          {expandido ? (
                            <ChevronUp className="w-5 h-5 text-gray-400" />
                          ) : (
                            <ChevronDown className="w-5 h-5 text-gray-400" />
                          )}
                        </div>
                      </div>
                    </button>
                    
                    {/* Detalhes expandidos */}
                    {expandido && (
                      <div className="mt-4 pt-4 border-t border-gray-100 space-y-4">
                        {achado.descricao && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-700 mb-1">Descrição Detalhada</h4>
                            <p className="text-sm text-gray-600">{achado.descricao}</p>
                          </div>
                        )}
                        
                        {achado.recomendacao && (
                          <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg">
                            <h4 className="text-sm font-medium text-blue-800 mb-1">Recomendação</h4>
                            <p className="text-sm text-blue-700">{achado.recomendacao}</p>
                          </div>
                        )}
                        
                        {achado.evidencia && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-700 mb-1">Evidências</h4>
                            <pre className="text-xs bg-gray-50 p-3 rounded-lg overflow-x-auto">
                              {JSON.stringify(achado.evidencia, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
      
      {abaAtiva === 'fontes' && (
        <div className="card">
          <div className="mb-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-3 bg-green-50 rounded-lg">
                <p className="text-sm text-green-700">Sucesso</p>
                <p className="text-xl font-bold text-green-800">{resumoExecucoes?.sucesso || 0}</p>
              </div>
              <div className="p-3 bg-red-50 rounded-lg">
                <p className="text-sm text-red-700">Erro</p>
                <p className="text-xl font-bold text-red-800">{resumoExecucoes?.erro || 0}</p>
              </div>
              <div className="p-3 bg-amber-50 rounded-lg">
                <p className="text-sm text-amber-700">Chave Ausente</p>
                <p className="text-xl font-bold text-amber-800">{resumoExecucoes?.chaveAusente || 0}</p>
              </div>
              <div className="p-3 bg-blue-50 rounded-lg">
                <p className="text-sm text-blue-700">Cache</p>
                <p className="text-xl font-bold text-blue-800">{resumoExecucoes?.cache || 0}</p>
              </div>
            </div>
          </div>
          
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Fonte</th>
                  <th>Consulta</th>
                  <th>Status</th>
                  <th>Itens</th>
                  <th>Duração</th>
                  <th>Cache</th>
                </tr>
              </thead>
              <tbody>
                {execucoesFonte?.map((exec: any) => (
                  <tr key={exec.id}>
                    <td className="font-medium">{exec.fonte}</td>
                    <td className="font-mono text-xs max-w-xs truncate">{exec.consulta}</td>
                    <td>
                      <span className={`badge ${
                        exec.status === 'SUCESSO' || exec.status === 'CACHE' ? 'badge-baixo' :
                        exec.status === 'ERRO' || exec.status === 'TIMEOUT' ? 'badge-critico' :
                        exec.status === 'CHAVE_AUSENTE' ? 'badge-medio' :
                        'status-aguardando'
                      }`}>
                        {exec.status === 'SUCESSO' ? 'Sucesso' :
                         exec.status === 'CACHE' ? 'Cache' :
                         exec.status === 'ERRO' ? 'Erro' :
                         exec.status === 'TIMEOUT' ? 'Timeout' :
                         exec.status === 'CHAVE_AUSENTE' ? 'Chave ausente' :
                         exec.status === 'LIMITE_TAXA' ? 'Rate limit' :
                         exec.status}
                      </span>
                    </td>
                    <td>{exec.itensEncontrados ?? '-'}</td>
                    <td>{exec.duracaoMs ? `${(exec.duracaoMs / 1000).toFixed(1)}s` : '-'}</td>
                    <td>{exec.usouCache ? '✓' : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          {execucoesFonte?.some((e: any) => e.mensagemErro) && (
            <div className="mt-4 pt-4 border-t border-gray-100">
              <h4 className="font-medium text-gray-900 mb-2">Mensagens de Erro</h4>
              <div className="space-y-2">
                {execucoesFonte.filter((e: any) => e.mensagemErro).map((e: any) => (
                  <div key={e.id} className="p-2 bg-red-50 rounded text-sm">
                    <span className="font-medium text-red-800">{e.fonte}:</span>
                    <span className="text-red-700 ml-2">{e.mensagemErro}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
