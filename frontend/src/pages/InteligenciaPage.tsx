// ============================================================================
// SENTINELA - Página de Inteligência de Ameaças
// Visualização de VulnClasses, Scoring e LGPD Crosswalk
// ============================================================================

import { useState, useEffect } from 'react';
import {
  Brain,
  Shield,
  Scale,
  Target,
  ChevronRight,
  Search,
  AlertTriangle,
  AlertOctagon,
  ShieldCheck,
  Info,
  Zap,
  Eye,
  Database,
  Users,
} from 'lucide-react';
import { api, VulnClass, ScoringResult } from '../services/api';
import VulnClassCard from '../components/VulnClassCard';
import ScoringAxesChart, { ScoringRadarChart } from '../components/ScoringAxesChart';
import LGPDCrosswalk from '../components/LGPDCrosswalk';

export default function InteligenciaPage() {
  const [vulnClasses, setVulnClasses] = useState<VulnClass[]>([]);
  const [carregando, setCarregando] = useState(true);
  const [classesSelecionada, setClasseSelecionada] = useState<VulnClass | null>(null);
  const [abaAtiva, setAbaAtiva] = useState<'vulnclasses' | 'scoring' | 'lgpd'>('vulnclasses');
  const [filtroSeveridade, setFiltroSeveridade] = useState<string>('');
  
  // Estado para simulação de scoring
  const [simulacao, setSimulacao] = useState({
    fonte: 'HIBP',
    tipo: 'CREDENTIAL_LEAK',
    titulo: 'Vazamento de credenciais',
    descricao: 'Credenciais encontradas em breach',
    nivelRisco: 'ALTO',
    count: 50,
  });
  const [resultadoScoring, setResultadoScoring] = useState<ScoringResult | null>(null);
  const [calculandoScore, setCalculandoScore] = useState(false);

  useEffect(() => {
    carregarVulnClasses();
  }, []);

  const carregarVulnClasses = async () => {
    try {
      const resposta = await api.getVulnClasses();
      setVulnClasses(resposta.vulnClasses || []);
    } catch (erro) {
      console.error('Erro ao carregar VulnClasses:', erro);
    } finally {
      setCarregando(false);
    }
  };

  const calcularScore = async () => {
    setCalculandoScore(true);
    try {
      const resultado = await api.calcularScoring({
        fonte: simulacao.fonte,
        tipo: simulacao.tipo,
        dados: {
          titulo: simulacao.titulo,
          descricao: simulacao.descricao,
          nivelRisco: simulacao.nivelRisco,
          count: simulacao.count,
        },
      });
      setResultadoScoring(resultado);
    } catch (erro) {
      console.error('Erro ao calcular score:', erro);
    } finally {
      setCalculandoScore(false);
    }
  };

  const vulnClassesFiltradas = vulnClasses.filter(
    (vc) => !filtroSeveridade || vc.severity === filtroSeveridade
  );

  const estatisticas = {
    total: vulnClasses.length,
    criticos: vulnClasses.filter((vc) => vc.severity === 'CRITICO').length,
    altos: vulnClasses.filter((vc) => vc.severity === 'ALTO').length,
    medios: vulnClasses.filter((vc) => vc.severity === 'MEDIO').length,
    baixos: vulnClasses.filter((vc) => vc.severity === 'BAIXO').length,
    comNotificacao: vulnClasses.filter((vc) => vc.lgpd?.notificationRequired).length,
  };

  return (
    <div className="space-y-6">
      {/* Cabeçalho */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-3">
          <Brain className="w-8 h-8 text-primary-600" />
          Inteligência de Ameaças
        </h1>
        <p className="text-gray-500 mt-1">
          Sistema de classificação, scoring e conformidade LGPD para achados de segurança
        </p>
      </div>

      {/* Cards de Estatísticas */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="card text-center">
          <Shield className="w-8 h-8 mx-auto text-primary-600 mb-2" />
          <p className="text-2xl font-bold text-gray-900">{estatisticas.total}</p>
          <p className="text-xs text-gray-500">VulnClasses</p>
        </div>
        <div className="card text-center">
          <AlertOctagon className="w-8 h-8 mx-auto text-red-600 mb-2" />
          <p className="text-2xl font-bold text-red-600">{estatisticas.criticos}</p>
          <p className="text-xs text-gray-500">Críticos</p>
        </div>
        <div className="card text-center">
          <AlertTriangle className="w-8 h-8 mx-auto text-orange-600 mb-2" />
          <p className="text-2xl font-bold text-orange-600">{estatisticas.altos}</p>
          <p className="text-xs text-gray-500">Altos</p>
        </div>
        <div className="card text-center">
          <Shield className="w-8 h-8 mx-auto text-amber-600 mb-2" />
          <p className="text-2xl font-bold text-amber-600">{estatisticas.medios}</p>
          <p className="text-xs text-gray-500">Médios</p>
        </div>
        <div className="card text-center">
          <ShieldCheck className="w-8 h-8 mx-auto text-green-600 mb-2" />
          <p className="text-2xl font-bold text-green-600">{estatisticas.baixos}</p>
          <p className="text-xs text-gray-500">Baixos</p>
        </div>
        <div className="card text-center">
          <Scale className="w-8 h-8 mx-auto text-purple-600 mb-2" />
          <p className="text-2xl font-bold text-purple-600">{estatisticas.comNotificacao}</p>
          <p className="text-xs text-gray-500">Req. ANPD</p>
        </div>
      </div>

      {/* Abas */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-6">
          <button
            onClick={() => setAbaAtiva('vulnclasses')}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
              abaAtiva === 'vulnclasses'
                ? 'border-primary-500 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <Shield className="w-4 h-4" />
            8 VulnClasses
          </button>
          <button
            onClick={() => setAbaAtiva('scoring')}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
              abaAtiva === 'scoring'
                ? 'border-primary-500 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <Target className="w-4 h-4" />
            Scoring 5 Eixos
          </button>
          <button
            onClick={() => setAbaAtiva('lgpd')}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
              abaAtiva === 'lgpd'
                ? 'border-primary-500 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <Scale className="w-4 h-4" />
            LGPD Crosswalk
          </button>
        </nav>
      </div>

      {/* Conteúdo das Abas */}
      {abaAtiva === 'vulnclasses' && (
        <div className="space-y-6">
          {/* Filtros */}
          <div className="flex gap-2 flex-wrap">
            <button
              onClick={() => setFiltroSeveridade('')}
              className={`btn btn-sm ${!filtroSeveridade ? 'btn-primary' : 'btn-secondary'}`}
            >
              Todas
            </button>
            {['CRITICO', 'ALTO', 'MEDIO', 'BAIXO'].map((sev) => (
              <button
                key={sev}
                onClick={() => setFiltroSeveridade(sev)}
                className={`btn btn-sm ${filtroSeveridade === sev ? 'btn-primary' : 'btn-secondary'}`}
              >
                {sev === 'CRITICO' ? 'Crítico' : sev === 'ALTO' ? 'Alto' : sev === 'MEDIO' ? 'Médio' : 'Baixo'}
              </button>
            ))}
          </div>

          {/* Lista de VulnClasses */}
          {carregando ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="card">
                  <div className="skeleton h-6 w-48 mb-2"></div>
                  <div className="skeleton h-4 w-full mb-4"></div>
                  <div className="skeleton h-20 w-full"></div>
                </div>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {vulnClassesFiltradas.map((vc) => (
                <VulnClassCard
                  key={vc.class}
                  vulnClass={vc}
                  onClick={() => setClasseSelecionada(vc)}
                />
              ))}
            </div>
          )}

          {/* Modal de Detalhes */}
          {classesSelecionada && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
              <div className="bg-white rounded-2xl shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
                <div className="p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-xl font-bold text-gray-900">Detalhes da VulnClass</h2>
                    <button
                      onClick={() => setClasseSelecionada(null)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      ✕
                    </button>
                  </div>
                  <VulnClassCard vulnClass={classesSelecionada} />
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {abaAtiva === 'scoring' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Formulário de Simulação */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-amber-600" />
              Simulador de Scoring
            </h3>
            <p className="text-sm text-gray-500 mb-4">
              Simule o cálculo de score para um achado hipotético
            </p>

            <div className="space-y-4">
              <div>
                <label className="label">Fonte de Inteligência</label>
                <select
                  value={simulacao.fonte}
                  onChange={(e) => setSimulacao({ ...simulacao, fonte: e.target.value })}
                  className="input"
                >
                  <option value="HIBP">Have I Been Pwned</option>
                  <option value="VT">VirusTotal</option>
                  <option value="SHODAN">Shodan</option>
                  <option value="LEAKIX">LeakIX</option>
                  <option value="HUDSON_ROCK">Hudson Rock</option>
                  <option value="GITHUB">GitHub</option>
                  <option value="URLSCAN">URLScan</option>
                </select>
              </div>

              <div>
                <label className="label">Tipo de Achado</label>
                <select
                  value={simulacao.tipo}
                  onChange={(e) => setSimulacao({ ...simulacao, tipo: e.target.value })}
                  className="input"
                >
                  <option value="CREDENTIAL_LEAK">Vazamento de Credenciais</option>
                  <option value="DATA_EXPOSURE">Exposição de Dados</option>
                  <option value="PHISHING">Phishing</option>
                  <option value="MALWARE">Malware</option>
                  <option value="VULNERABILITY">Vulnerabilidade</option>
                </select>
              </div>

              <div>
                <label className="label">Título</label>
                <input
                  type="text"
                  value={simulacao.titulo}
                  onChange={(e) => setSimulacao({ ...simulacao, titulo: e.target.value })}
                  className="input"
                />
              </div>

              <div>
                <label className="label">Descrição</label>
                <textarea
                  value={simulacao.descricao}
                  onChange={(e) => setSimulacao({ ...simulacao, descricao: e.target.value })}
                  className="input"
                  rows={2}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">Nível de Risco</label>
                  <select
                    value={simulacao.nivelRisco}
                    onChange={(e) => setSimulacao({ ...simulacao, nivelRisco: e.target.value })}
                    className="input"
                  >
                    <option value="CRITICO">Crítico</option>
                    <option value="ALTO">Alto</option>
                    <option value="MEDIO">Médio</option>
                    <option value="BAIXO">Baixo</option>
                  </select>
                </div>
                <div>
                  <label className="label">Registros Afetados</label>
                  <input
                    type="number"
                    value={simulacao.count}
                    onChange={(e) => setSimulacao({ ...simulacao, count: parseInt(e.target.value) || 0 })}
                    className="input"
                    min="1"
                  />
                </div>
              </div>

              <button
                onClick={calcularScore}
                disabled={calculandoScore}
                className="btn btn-primary w-full"
              >
                {calculandoScore ? 'Calculando...' : 'Calcular Score'}
              </button>
            </div>
          </div>

          {/* Resultado do Scoring */}
          <div className="space-y-6">
            {resultadoScoring ? (
              <>
                <div className="card">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Resultado do Scoring</h3>
                  <ScoringAxesChart
                    axes={resultadoScoring.scoreAxes}
                    scoreFinal={resultadoScoring.scoreFinal}
                    riskLevel={resultadoScoring.riskLevel.level}
                  />
                </div>

                <div className="card">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">VulnClass Identificada</h3>
                  <VulnClassCard vulnClass={resultadoScoring.vulnClassDetails} compact />
                </div>

                <LGPDCrosswalk
                  vulnClass={resultadoScoring.vulnClass}
                  articles={resultadoScoring.lgpd.articles}
                  anpdCriteria={resultadoScoring.lgpd.anpdCriteria}
                  notificationRequired={resultadoScoring.lgpd.notificationRequired}
                  deadlineDays={resultadoScoring.lgpd.deadlineDays}
                  recommendations={resultadoScoring.lgpd.recommendations}
                  compact
                />
              </>
            ) : (
              <div className="card text-center py-12">
                <Target className="w-16 h-16 mx-auto text-gray-300 mb-4" />
                <h3 className="text-lg font-semibold text-gray-700 mb-2">Nenhum Score Calculado</h3>
                <p className="text-gray-500">
                  Preencha os dados ao lado e clique em "Calcular Score" para ver o resultado
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {abaAtiva === 'lgpd' && (
        <div className="space-y-6">
          {/* Informativo */}
          <div className="p-6 bg-purple-50 border border-purple-200 rounded-2xl">
            <div className="flex items-start gap-4">
              <Scale className="w-8 h-8 text-purple-600 flex-shrink-0" />
              <div>
                <h3 className="text-lg font-semibold text-purple-900">Crosswalk LGPD/ANPD Res 15/2024</h3>
                <p className="text-purple-700 mt-1">
                  Cada VulnClass possui um mapeamento completo para os artigos da LGPD e critérios da Resolução CD/ANPD nº 15/2024,
                  incluindo a necessidade de comunicação à ANPD em caso de incidente de segurança.
                </p>
              </div>
            </div>
          </div>

          {/* Tabela de Mapeamento */}
          <div className="card overflow-x-auto">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Mapeamento por VulnClass</h3>
            <table className="table">
              <thead>
                <tr>
                  <th>VulnClass</th>
                  <th>Severidade</th>
                  <th>Artigos LGPD</th>
                  <th>Notificação ANPD</th>
                  <th>Prazo</th>
                </tr>
              </thead>
              <tbody>
                {vulnClasses.map((vc) => (
                  <tr key={vc.class}>
                    <td>
                      <div>
                        <p className="font-medium text-gray-900">{vc.name}</p>
                        <code className="text-xs text-gray-500">{vc.class}</code>
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${
                        vc.severity === 'CRITICO' ? 'badge-critico' :
                        vc.severity === 'ALTO' ? 'badge-alto' :
                        vc.severity === 'MEDIO' ? 'badge-medio' : 'badge-baixo'
                      }`}>
                        {vc.severity}
                      </span>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {vc.lgpd?.articles.map((art) => (
                          <span key={art} className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded">
                            {art}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      {vc.lgpd?.notificationRequired ? (
                        <span className="badge bg-red-100 text-red-700">Obrigatória</span>
                      ) : (
                        <span className="badge bg-gray-100 text-gray-600">Não requerida</span>
                      )}
                    </td>
                    <td>
                      {vc.lgpd?.notificationRequired ? (
                        <span className="text-red-600 font-semibold">3 dias úteis</span>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Artigos LGPD Mais Comuns */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Artigos LGPD Mais Relevantes</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { art: 'Art. 46', titulo: 'Segurança e Sigilo', desc: 'Medidas de segurança técnicas e administrativas' },
                { art: 'Art. 47', titulo: 'Comunicação de Incidentes', desc: 'Dever de comunicar incidentes de segurança' },
                { art: 'Art. 48', titulo: 'Comunicação à ANPD', desc: 'Comunicação em caso de risco ou dano ao titular' },
                { art: 'Art. 52', titulo: 'Sanções Administrativas', desc: 'Multas de até 2% do faturamento' },
              ].map((item) => (
                <div key={item.art} className="p-4 bg-gray-50 rounded-xl border border-gray-200">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-semibold text-primary-700">{item.art}</span>
                    <span className="text-gray-700">- {item.titulo}</span>
                  </div>
                  <p className="text-sm text-gray-600">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
