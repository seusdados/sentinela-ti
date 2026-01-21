// ============================================================================
// SENTINELA - Componente de LGPD Crosswalk
// Exibe o mapeamento LGPD/ANPD Res 15/2024 para achados
// ============================================================================

import {
  Scale,
  Bell,
  Clock,
  FileText,
  CheckCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Gavel,
} from 'lucide-react';
import { useState } from 'react';

interface LGPDArticle {
  number: string;
  title: string;
  description: string;
  relevance: string;
}

interface ANPDCriterion {
  name: string;
  description: string;
  requiresNotification: boolean;
}

interface LGPDCrosswalkProps {
  vulnClass: string;
  articles: string[];
  anpdCriteria?: string[];
  notificationRequired: boolean;
  deadlineDays?: number | null;
  recommendations?: string[];
  applicableArticles?: LGPDArticle[];
  anpdCriteriaDetails?: ANPDCriterion[];
  compact?: boolean;
}

// Informações dos artigos LGPD mais comuns
const ARTIGOS_LGPD: Record<string, { titulo: string; resumo: string }> = {
  'Art. 18': {
    titulo: 'Direitos do Titular',
    resumo: 'Direitos de acesso, correção, anonimização, portabilidade e eliminação de dados.',
  },
  'Art. 42': {
    titulo: 'Responsabilidade e Ressarcimento',
    resumo: 'Controlador ou operador que causar dano patrimonial, moral, individual ou coletivo.',
  },
  'Art. 46': {
    titulo: 'Segurança e Sigilo',
    resumo: 'Medidas de segurança técnicas e administrativas para proteção de dados pessoais.',
  },
  'Art. 47': {
    titulo: 'Comunicação de Incidentes',
    resumo: 'Dever de comunicar à autoridade e ao titular incidentes de segurança.',
  },
  'Art. 48': {
    titulo: 'Comunicação à ANPD',
    resumo: 'Comunicação à ANPD e ao titular em caso de incidente que possa acarretar risco ou dano.',
  },
  'Art. 52': {
    titulo: 'Sanções Administrativas',
    resumo: 'Multas de até 2% do faturamento, limitada a R$ 50 milhões por infração.',
  },
};

export default function LGPDCrosswalk({
  vulnClass,
  articles,
  anpdCriteria = [],
  notificationRequired,
  deadlineDays,
  recommendations = [],
  applicableArticles = [],
  anpdCriteriaDetails = [],
  compact = false,
}: LGPDCrosswalkProps) {
  const [expandido, setExpandido] = useState(!compact);

  if (compact) {
    return (
      <div className={`p-4 rounded-xl ${notificationRequired ? 'bg-red-50 border border-red-200' : 'bg-blue-50 border border-blue-200'}`}>
        <button
          onClick={() => setExpandido(!expandido)}
          className="w-full flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <Scale className={`w-5 h-5 ${notificationRequired ? 'text-red-600' : 'text-blue-600'}`} />
            <div className="text-left">
              <h4 className={`font-semibold ${notificationRequired ? 'text-red-700' : 'text-blue-700'}`}>
                Conformidade LGPD
              </h4>
              <p className="text-xs text-gray-500">
                {articles.length} artigo(s) aplicável(is)
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {notificationRequired && (
              <span className="flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-100 px-2 py-1 rounded-full">
                <Bell className="w-3 h-3" />
                ANPD
              </span>
            )}
            {expandido ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
          </div>
        </button>

        {expandido && (
          <div className="mt-4 pt-4 border-t border-gray-200 space-y-3">
            {/* Artigos */}
            <div className="flex flex-wrap gap-2">
              {articles.map((art) => (
                <span key={art} className="text-xs bg-white px-2 py-1 rounded border border-gray-200 text-gray-700">
                  {art}
                </span>
              ))}
            </div>

            {/* Notificação ANPD */}
            {notificationRequired && deadlineDays && (
              <div className="flex items-center gap-2 text-red-700 bg-red-100 p-2 rounded-lg">
                <Clock className="w-4 h-4" />
                <span className="text-sm font-medium">
                  Prazo de {deadlineDays} dias úteis para comunicação à ANPD
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Cabeçalho */}
      <div className={`p-6 rounded-2xl ${notificationRequired ? 'bg-red-50 border border-red-200' : 'bg-blue-50 border border-blue-200'}`}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-4">
            <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${notificationRequired ? 'bg-red-100' : 'bg-blue-100'}`}>
              <Scale className={`w-7 h-7 ${notificationRequired ? 'text-red-600' : 'text-blue-600'}`} />
            </div>
            <div>
              <h3 className={`text-lg font-bold ${notificationRequired ? 'text-red-700' : 'text-blue-700'}`}>
                Conformidade LGPD
              </h3>
              <p className="text-sm text-gray-600">
                Mapeamento para {vulnClass}
              </p>
            </div>
          </div>
          {notificationRequired && (
            <div className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded-lg">
              <Bell className="w-5 h-5" />
              <span className="font-semibold">Notificação ANPD Obrigatória</span>
            </div>
          )}
        </div>

        {/* Prazo */}
        {notificationRequired && deadlineDays && (
          <div className="flex items-center gap-3 p-4 bg-white rounded-xl border border-red-200">
            <Clock className="w-6 h-6 text-red-600" />
            <div>
              <p className="font-semibold text-red-700">Prazo: {deadlineDays} dias úteis</p>
              <p className="text-sm text-gray-600">
                Conforme Resolução CD/ANPD nº 15/2024, a comunicação deve ser feita em até {deadlineDays} dias úteis após o conhecimento do incidente.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Artigos Aplicáveis */}
      <div className="card">
        <h4 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Gavel className="w-5 h-5 text-primary-600" />
          Artigos LGPD Aplicáveis
        </h4>
        <div className="space-y-3">
          {articles.map((art) => {
            const info = ARTIGOS_LGPD[art] || { titulo: art, resumo: '' };
            const detalhe = applicableArticles.find(a => a.number === art);
            return (
              <div key={art} className="p-4 bg-gray-50 rounded-xl border border-gray-200">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-primary-700">{art}</span>
                      <span className="text-gray-700">- {detalhe?.title || info.titulo}</span>
                    </div>
                    <p className="text-sm text-gray-600 mt-1">
                      {detalhe?.description || info.resumo}
                    </p>
                    {detalhe?.relevance && (
                      <p className="text-xs text-primary-600 mt-2 italic">
                        Relevância: {detalhe.relevance}
                      </p>
                    )}
                  </div>
                  <a
                    href={`https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm#${art.toLowerCase().replace('. ', '')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary-600 hover:text-primary-700"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Critérios ANPD */}
      {anpdCriteria.length > 0 && (
        <div className="card">
          <h4 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <FileText className="w-5 h-5 text-amber-600" />
            Critérios ANPD Res 15/2024
          </h4>
          <div className="space-y-2">
            {anpdCriteria.map((criterio, i) => {
              const detalhe = anpdCriteriaDetails.find(c => c.name === criterio);
              return (
                <div key={i} className="flex items-start gap-3 p-3 bg-amber-50 rounded-lg border border-amber-200">
                  {detalhe?.requiresNotification ? (
                    <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
                  )}
                  <div>
                    <p className="font-medium text-amber-800">{criterio}</p>
                    {detalhe?.description && (
                      <p className="text-sm text-amber-700 mt-1">{detalhe.description}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Recomendações */}
      {recommendations.length > 0 && (
        <div className="card">
          <h4 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <CheckCircle className="w-5 h-5 text-green-600" />
            Recomendações de Ação
          </h4>
          <div className="space-y-2">
            {recommendations.map((rec, i) => (
              <div key={i} className="flex items-start gap-3 p-3 bg-green-50 rounded-lg border border-green-200">
                <div className="w-6 h-6 rounded-full bg-green-600 text-white flex items-center justify-center text-sm font-semibold flex-shrink-0">
                  {i + 1}
                </div>
                <p className="text-green-800">{rec}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Badge compacto para indicar status LGPD
export function LGPDBadge({ notificationRequired, articles }: { notificationRequired: boolean; articles: string[] }) {
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
      notificationRequired ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'
    }`}>
      <Scale className="w-4 h-4" />
      <span className="font-medium">LGPD</span>
      {notificationRequired && (
        <>
          <span className="w-1 h-1 rounded-full bg-current" />
          <Bell className="w-3 h-3" />
          <span className="text-xs">ANPD</span>
        </>
      )}
    </div>
  );
}
