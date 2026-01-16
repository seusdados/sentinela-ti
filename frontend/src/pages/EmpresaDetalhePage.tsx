// ============================================================================
// SENTINELA - Página de Detalhe da Empresa
// ============================================================================

import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  Building2,
  Globe,
  Radar,
  ArrowLeft,
  Play,
  Shield,
  Clock,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../services/api';

export default function EmpresaDetalhePage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [empresa, setEmpresa] = useState<any>(null);
  const [carregando, setCarregando] = useState(true);
  const [iniciandoVarredura, setIniciandoVarredura] = useState(false);
  
  useEffect(() => {
    carregarEmpresa();
  }, [id]);
  
  const carregarEmpresa = async () => {
    try {
      const resposta = await api.getEmpresa(id!);
      setEmpresa(resposta.empresa);
    } catch (erro) {
      console.error('Erro ao carregar empresa:', erro);
    } finally {
      setCarregando(false);
    }
  };
  
  const iniciarVarredura = async () => {
    setIniciandoVarredura(true);
    try {
      const resposta = await api.criarVarredura({
        empresaId: id,
        escopo: 'COMPLETO',
        varreduraProfunda: true,
      });
      navigate(`/varreduras/${resposta.varredura.id}`);
    } catch (erro) {
      console.error('Erro ao iniciar varredura:', erro);
    } finally {
      setIniciandoVarredura(false);
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
  
  if (!empresa) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Empresa não encontrada</p>
        <Link to="/empresas" className="btn btn-primary mt-4">
          Voltar para lista
        </Link>
      </div>
    );
  }
  
  return (
    <div className="space-y-6">
      {/* Navegação */}
      <Link to="/empresas" className="inline-flex items-center gap-2 text-gray-500 hover:text-gray-700">
        <ArrowLeft className="w-4 h-4" />
        Voltar para empresas
      </Link>
      
      {/* Cabeçalho */}
      <div className="card">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-primary-100 flex items-center justify-center">
              <Building2 className="w-8 h-8 text-primary-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{empresa.nome}</h1>
              {empresa.nomeFantasia && (
                <p className="text-gray-500">{empresa.nomeFantasia}</p>
              )}
              {empresa.cnpj && (
                <p className="text-sm text-gray-400">CNPJ: {empresa.cnpj}</p>
              )}
            </div>
          </div>
          <button
            onClick={iniciarVarredura}
            disabled={iniciandoVarredura}
            className="btn btn-primary"
          >
            {iniciandoVarredura ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                Iniciando...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Iniciar Nova Varredura
              </>
            )}
          </button>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Informações */}
        <div className="lg:col-span-2 space-y-6">
          {/* Domínios */}
          <div className="card">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Domínios Monitorados</h2>
            <div className="space-y-2">
              {empresa.dominios?.map((d: any) => (
                <div key={d.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <Globe className="w-5 h-5 text-gray-400" />
                    <span className="font-medium">{d.dominio}</span>
                    {d.principal && (
                      <span className="badge badge-info text-[10px]">Principal</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
          
          {/* Últimas Varreduras */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-900">Últimas Varreduras</h2>
              <Link to={`/varreduras?empresaId=${id}`} className="text-primary-600 text-sm hover:underline">
                Ver todas
              </Link>
            </div>
            
            {empresa.varreduras?.length > 0 ? (
              <div className="space-y-3">
                {empresa.varreduras.map((v: any) => (
                  <Link
                    key={v.id}
                    to={`/varreduras/${v.id}`}
                    className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Radar className="w-5 h-5 text-gray-400" />
                      <div>
                        <span className="font-medium text-gray-900">
                          Varredura #{v.id.slice(0, 8)}
                        </span>
                        <p className="text-xs text-gray-500">
                          {new Date(v.criadoEm).toLocaleDateString('pt-BR')}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`badge ${
                        v.status === 'CONCLUIDA' ? 'badge-baixo' :
                        v.status === 'EXECUTANDO' ? 'badge-info' :
                        v.status === 'FALHOU' ? 'badge-critico' : 'status-aguardando'
                      }`}>
                        {v.status === 'CONCLUIDA' ? 'Concluída' :
                         v.status === 'EXECUTANDO' ? 'Em execução' :
                         v.status === 'FALHOU' ? 'Falhou' : 'Aguardando'}
                      </span>
                      <span className="text-sm text-gray-500">{v.totalAchados} achados</span>
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-400">
                <Radar className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>Nenhuma varredura realizada</p>
              </div>
            )}
          </div>
        </div>
        
        {/* Sidebar */}
        <div className="space-y-6">
          {/* Status de Monitoramento */}
          <div className="card">
            <h3 className="font-semibold text-gray-900 mb-4">Status de Monitoramento</h3>
            {empresa.monitoramento?.ativo ? (
              <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
                <div className="flex items-center gap-2 text-green-700">
                  <Shield className="w-5 h-5" />
                  <span className="font-medium">Monitoramento Ativo</span>
                </div>
                <p className="text-sm text-green-600 mt-1">
                  Frequência: {empresa.monitoramento.frequencia}
                </p>
              </div>
            ) : (
              <div className="p-3 bg-gray-50 border border-gray-200 rounded-lg">
                <div className="flex items-center gap-2 text-gray-600">
                  <Shield className="w-5 h-5 opacity-50" />
                  <span>Monitoramento Inativo</span>
                </div>
              </div>
            )}
          </div>
          
          {/* Informações de Contato */}
          {(empresa.emailPrincipal || empresa.nomeDpo) && (
            <div className="card">
              <h3 className="font-semibold text-gray-900 mb-4">Contato</h3>
              <div className="space-y-3">
                {empresa.emailPrincipal && (
                  <div>
                    <p className="text-xs text-gray-500">E-mail principal</p>
                    <p className="text-sm">{empresa.emailPrincipal}</p>
                  </div>
                )}
                {empresa.nomeDpo && (
                  <div>
                    <p className="text-xs text-gray-500">DPO</p>
                    <p className="text-sm">{empresa.nomeDpo}</p>
                    {empresa.emailDpo && (
                      <p className="text-sm text-gray-500">{empresa.emailDpo}</p>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
