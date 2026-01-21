// ============================================================================
// SENTINELA - Dashboard Principal
// Visão geral da segurança corporativa
// ============================================================================

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Building2,
  Radar,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  TrendingDown,
  ArrowRight,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  Brain,
  Scale,
  Target,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { api } from '../services/api';

const CORES_RISCO = {
  CRITICO: '#dc2626',
  ALTO: '#ea580c',
  MEDIO: '#d97706',
  BAIXO: '#16a34a',
  INFORMATIVO: '#0ea5e9',
};

const NOMES_RISCO = {
  CRITICO: 'Crítico',
  ALTO: 'Alto',
  MEDIO: 'Médio',
  BAIXO: 'Baixo',
  INFORMATIVO: 'Informativo',
};

const CORES_FONTE = {
  CRTSH: '#6366f1',
  SHODAN: '#ec4899',
  LEAKIX: '#f59e0b',
  VIRUSTOTAL: '#10b981',
  HIBP: '#ef4444',
  URLSCAN: '#8b5cf6',
  OTX: '#06b6d4',
  GITHUB: '#1f2937',
  ABUSEIPDB: '#f97316',
  PSBDMP: '#84cc16',
};

function formatarData(data: string) {
  return new Date(data).toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function DashboardPage() {
  const [dados, setDados] = useState<any>(null);
  const [carregando, setCarregando] = useState(true);
  
  useEffect(() => {
    carregarDados();
  }, []);
  
  const carregarDados = async () => {
    try {
      const resposta = await api.getDashboard();
      setDados(resposta);
    } catch (erro) {
      console.error('Erro ao carregar dashboard:', erro);
    } finally {
      setCarregando(false);
    }
  };
  
  if (carregando) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="card">
              <div className="skeleton h-4 w-24 mb-3"></div>
              <div className="skeleton h-8 w-16 mb-2"></div>
              <div className="skeleton h-3 w-32"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }
  
  const { estatisticas, ultimasVarreduras, ultimosAchados, distribuicaoPorRisco, distribuicaoPorFonte } = dados || {};
  
  // Preparar dados para gráfico de pizza
  const dadosRisco = Object.entries(distribuicaoPorRisco || {}).map(([nivel, count]) => ({
    name: NOMES_RISCO[nivel as keyof typeof NOMES_RISCO] || nivel,
    value: count as number,
    color: CORES_RISCO[nivel as keyof typeof CORES_RISCO] || '#9ca3af',
  }));
  
  // Preparar dados para gráfico de barras
  const dadosFonte = Object.entries(distribuicaoPorFonte || {}).map(([fonte, count]) => ({
    fonte,
    quantidade: count as number,
    fill: CORES_FONTE[fonte as keyof typeof CORES_FONTE] || '#9ca3af',
  })).sort((a, b) => b.quantidade - a.quantidade).slice(0, 8);
  
  return (
    <div className="space-y-6">
      {/* Título */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Painel Geral</h1>
        <p className="text-gray-500 mt-1">Visão consolidada da segurança das empresas monitoradas</p>
      </div>
      
      {/* Cards de Métricas */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="card">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-blue-100 flex items-center justify-center">
              <Building2 className="w-5 h-5 text-blue-600" />
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900">{estatisticas?.totalEmpresas || 0}</div>
          <div className="text-sm text-gray-500 mt-1">Empresas cadastradas</div>
          <div className="text-xs text-primary-600 font-medium mt-2">
            {estatisticas?.empresasMonitoradas || 0} em monitoramento ativo
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-purple-100 flex items-center justify-center">
              <Radar className="w-5 h-5 text-purple-600" />
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900">{estatisticas?.varredurasUltimos30Dias || 0}</div>
          <div className="text-sm text-gray-500 mt-1">Varreduras nos últimos 30 dias</div>
          <div className="text-xs text-green-600 font-medium mt-2 flex items-center gap-1">
            <TrendingUp className="w-3 h-3" />
            Sistema operacional
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-red-100 flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-red-600" />
            </div>
          </div>
          <div className="text-3xl font-bold text-red-600">{estatisticas?.achadosCriticos || 0}</div>
          <div className="text-sm text-gray-500 mt-1">Achados críticos abertos</div>
          <div className="text-xs text-red-600 font-medium mt-2">
            Requerem atenção imediata
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-orange-100 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-orange-600" />
            </div>
          </div>
          <div className="text-3xl font-bold text-orange-600">{estatisticas?.achadosAltos || 0}</div>
          <div className="text-sm text-gray-500 mt-1">Achados de risco alto</div>
          <div className="text-xs text-orange-600 font-medium mt-2">
            Prioridade elevada
          </div>
        </div>
      </div>
      
      {/* Card de Inteligência de Ameaças */}
      <div className="card bg-gradient-to-br from-primary-50 to-purple-50 border-primary-200">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-primary-100 flex items-center justify-center">
              <Brain className="w-7 h-7 text-primary-600" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-gray-900">Inteligência de Ameaças</h3>
              <p className="text-sm text-gray-600">Sistema de classificação, scoring e conformidade LGPD</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <div className="flex items-center gap-2 px-3 py-2 bg-white rounded-lg border border-gray-200">
              <Target className="w-4 h-4 text-amber-600" />
              <span className="text-sm font-medium text-gray-700">Scoring 5 Eixos</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-2 bg-white rounded-lg border border-gray-200">
              <ShieldAlert className="w-4 h-4 text-red-600" />
              <span className="text-sm font-medium text-gray-700">8 VulnClasses</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-2 bg-white rounded-lg border border-gray-200">
              <Scale className="w-4 h-4 text-purple-600" />
              <span className="text-sm font-medium text-gray-700">LGPD Crosswalk</span>
            </div>
            <Link to="/inteligencia" className="btn btn-primary btn-sm">
              Acessar <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </div>
      
      {/* Gráficos */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Distribuição por Nível de Risco */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Distribuição por Nível de Risco</h3>
              <p className="card-description">Achados abertos classificados por criticidade</p>
            </div>
          </div>
          
          {dadosRisco.length > 0 ? (
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={dadosRisco}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {dadosRisco.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    formatter={(value: number) => [`${value} achados`, 'Quantidade']}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-[280px] flex items-center justify-center text-gray-400">
              <div className="text-center">
                <ShieldCheck className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>Nenhum achado encontrado</p>
              </div>
            </div>
          )}
        </div>
        
        {/* Distribuição por Fonte */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Achados por Fonte de Inteligência</h3>
              <p className="card-description">Quantidade de descobertas por provedor</p>
            </div>
          </div>
          
          {dadosFonte.length > 0 ? (
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dadosFonte} layout="vertical" margin={{ left: 70 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} />
                  <XAxis type="number" />
                  <YAxis type="category" dataKey="fonte" tick={{ fontSize: 12 }} />
                  <Tooltip 
                    formatter={(value: number) => [`${value} achados`, 'Quantidade']}
                  />
                  <Bar dataKey="quantidade" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-[280px] flex items-center justify-center text-gray-400">
              <div className="text-center">
                <Radar className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>Nenhum dado disponível</p>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Tabelas */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Últimas Varreduras */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Últimas Varreduras</h3>
              <p className="card-description">Execuções mais recentes</p>
            </div>
            <Link to="/varreduras" className="btn btn-ghost btn-sm">
              Ver todas <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Empresa</th>
                  <th>Status</th>
                  <th>Achados</th>
                  <th>Data</th>
                </tr>
              </thead>
              <tbody>
                {(ultimasVarreduras || []).map((v: any) => (
                  <tr key={v.id}>
                    <td>
                      <Link to={`/varreduras/${v.id}`} className="font-medium text-gray-900 hover:text-primary-600">
                        {v.empresa}
                      </Link>
                    </td>
                    <td>
                      <span className={`badge ${
                        v.status === 'CONCLUIDA' ? 'badge-baixo' :
                        v.status === 'EXECUTANDO' ? 'badge-info' :
                        v.status === 'FALHOU' ? 'badge-critico' :
                        'status-aguardando'
                      }`}>
                        {v.status === 'CONCLUIDA' && <CheckCircle className="w-3 h-3 mr-1" />}
                        {v.status === 'EXECUTANDO' && <Clock className="w-3 h-3 mr-1 animate-spin" />}
                        {v.status === 'FALHOU' && <XCircle className="w-3 h-3 mr-1" />}
                        {v.status === 'AGUARDANDO' && <Clock className="w-3 h-3 mr-1" />}
                        {v.status === 'CONCLUIDA' ? 'Concluída' :
                         v.status === 'EXECUTANDO' ? 'Em execução' :
                         v.status === 'FALHOU' ? 'Falhou' : 'Aguardando'}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{v.totalAchados}</span>
                        {v.achadosCriticos > 0 && (
                          <span className="badge badge-critico text-[10px] px-1.5 py-0.5">
                            {v.achadosCriticos} críticos
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="text-gray-500 text-sm">{formatarData(v.criadoEm)}</td>
                  </tr>
                ))}
                {(!ultimasVarreduras || ultimasVarreduras.length === 0) && (
                  <tr>
                    <td colSpan={4} className="text-center text-gray-400 py-8">
                      Nenhuma varredura realizada ainda
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        
        {/* Últimos Achados */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Achados Recentes</h3>
              <p className="card-description">Últimas descobertas de segurança</p>
            </div>
          </div>
          
          <div className="space-y-3">
            {(ultimosAchados || []).slice(0, 6).map((achado: any) => (
              <div
                key={achado.id}
                className="p-3 rounded-xl bg-gray-50 hover:bg-gray-100 transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${
                    achado.nivelRisco === 'CRITICO' ? 'bg-red-500' :
                    achado.nivelRisco === 'ALTO' ? 'bg-orange-500' :
                    achado.nivelRisco === 'MEDIO' ? 'bg-amber-500' :
                    'bg-green-500'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <h4 className="text-sm font-medium text-gray-900 truncate">
                      {achado.titulo}
                    </h4>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs text-gray-500">{achado.fonte}</span>
                      <span className="text-gray-300">•</span>
                      <span className="text-xs text-gray-500">{achado.empresa}</span>
                    </div>
                  </div>
                  <span className={`badge text-[10px] ${
                    achado.nivelRisco === 'CRITICO' ? 'badge-critico' :
                    achado.nivelRisco === 'ALTO' ? 'badge-alto' :
                    achado.nivelRisco === 'MEDIO' ? 'badge-medio' :
                    'badge-baixo'
                  }`}>
                    {NOMES_RISCO[achado.nivelRisco as keyof typeof NOMES_RISCO] || achado.nivelRisco}
                  </span>
                </div>
              </div>
            ))}
            {(!ultimosAchados || ultimosAchados.length === 0) && (
              <div className="text-center text-gray-400 py-8">
                <ShieldCheck className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>Nenhum achado encontrado</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
