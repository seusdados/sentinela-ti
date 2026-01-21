// ============================================================================
// SENTINELA - Componente de Card de VulnClass
// Exibe informações detalhadas de uma classe de vulnerabilidade
// ============================================================================

import {
  Key,
  Globe,
  Mail,
  Bug,
  Server,
  Skull,
  UserX,
  Building2,
  AlertTriangle,
  AlertOctagon,
  Shield,
  ShieldCheck,
  ExternalLink,
  FileText,
  Scale,
  Bell,
} from 'lucide-react';

interface VulnClassCardProps {
  vulnClass: {
    class: string;
    name: string;
    description: string;
    severity: string;
    indicators: string[];
    sources: string[];
    defaultExposure: number;
    defaultExploitability: number;
    defaultDataSensitivity: number;
    lgpd?: {
      articles: string[];
      notificationRequired: boolean;
    };
  };
  onClick?: () => void;
  compact?: boolean;
}

const ICONES_VULN: Record<string, any> = {
  SECRETS_LEAK: Key,
  DATA_EXPOSURE_PUBLIC: Globe,
  PHISHING_SOCIAL_ENG: Mail,
  RANSOMWARE_IMPACT: Skull,
  UNPATCHED_EXPLOITED: Bug,
  MALWARE_C2: Server,
  ACCOUNT_TAKEOVER: UserX,
  THIRD_PARTY_RISK: Building2,
};

const CORES_SEVERIDADE = {
  CRITICO: { bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-700', badge: 'bg-red-100 text-red-800', icon: AlertOctagon },
  ALTO: { bg: 'bg-orange-50', border: 'border-orange-200', text: 'text-orange-700', badge: 'bg-orange-100 text-orange-800', icon: AlertTriangle },
  MEDIO: { bg: 'bg-amber-50', border: 'border-amber-200', text: 'text-amber-700', badge: 'bg-amber-100 text-amber-800', icon: Shield },
  BAIXO: { bg: 'bg-green-50', border: 'border-green-200', text: 'text-green-700', badge: 'bg-green-100 text-green-800', icon: ShieldCheck },
};

export default function VulnClassCard({ vulnClass, onClick, compact = false }: VulnClassCardProps) {
  const Icone = ICONES_VULN[vulnClass.class] || Shield;
  const cores = CORES_SEVERIDADE[vulnClass.severity as keyof typeof CORES_SEVERIDADE] || CORES_SEVERIDADE.MEDIO;
  const IconeSeveridade = cores.icon;

  if (compact) {
    return (
      <div
        onClick={onClick}
        className={`p-4 rounded-xl border ${cores.border} ${cores.bg} cursor-pointer hover:shadow-md transition-all`}
      >
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${cores.badge}`}>
            <Icone className="w-5 h-5" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className={`font-semibold ${cores.text} truncate`}>{vulnClass.name}</h3>
            <p className="text-xs text-gray-500 truncate">{vulnClass.description}</p>
          </div>
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${cores.badge}`}>
            {vulnClass.severity}
          </span>
        </div>
      </div>
    );
  }

  return (
    <div
      onClick={onClick}
      className={`p-6 rounded-2xl border ${cores.border} ${cores.bg} ${onClick ? 'cursor-pointer hover:shadow-lg' : ''} transition-all`}
    >
      {/* Cabeçalho */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-4">
          <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${cores.badge}`}>
            <Icone className="w-7 h-7" />
          </div>
          <div>
            <h3 className={`text-lg font-bold ${cores.text}`}>{vulnClass.name}</h3>
            <code className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">{vulnClass.class}</code>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <IconeSeveridade className={`w-5 h-5 ${cores.text}`} />
          <span className={`px-3 py-1 rounded-full text-sm font-semibold ${cores.badge}`}>
            {vulnClass.severity}
          </span>
        </div>
      </div>

      {/* Descrição */}
      <p className="text-gray-600 mb-4">{vulnClass.description}</p>

      {/* Indicadores */}
      <div className="mb-4">
        <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center gap-2">
          <FileText className="w-4 h-4" />
          Indicadores
        </h4>
        <div className="flex flex-wrap gap-2">
          {vulnClass.indicators.slice(0, 5).map((ind, i) => (
            <span key={i} className="text-xs bg-white px-2 py-1 rounded border border-gray-200 text-gray-600">
              {ind}
            </span>
          ))}
          {vulnClass.indicators.length > 5 && (
            <span className="text-xs text-gray-400">+{vulnClass.indicators.length - 5} mais</span>
          )}
        </div>
      </div>

      {/* Fontes */}
      <div className="mb-4">
        <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center gap-2">
          <ExternalLink className="w-4 h-4" />
          Fontes de Inteligência
        </h4>
        <div className="flex flex-wrap gap-2">
          {vulnClass.sources.map((source, i) => (
            <span key={i} className="text-xs bg-blue-50 text-blue-700 px-2 py-1 rounded border border-blue-200">
              {source}
            </span>
          ))}
        </div>
      </div>

      {/* Scores Padrão */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="text-center p-2 bg-white rounded-lg border border-gray-200">
          <p className="text-xs text-gray-500">Exposição</p>
          <p className="text-lg font-bold text-blue-600">{Math.round(vulnClass.defaultExposure * 100)}%</p>
        </div>
        <div className="text-center p-2 bg-white rounded-lg border border-gray-200">
          <p className="text-xs text-gray-500">Explorabilidade</p>
          <p className="text-lg font-bold text-amber-600">{Math.round(vulnClass.defaultExploitability * 100)}%</p>
        </div>
        <div className="text-center p-2 bg-white rounded-lg border border-gray-200">
          <p className="text-xs text-gray-500">Sensibilidade</p>
          <p className="text-lg font-bold text-red-600">{Math.round(vulnClass.defaultDataSensitivity * 100)}%</p>
        </div>
      </div>

      {/* LGPD */}
      {vulnClass.lgpd && (
        <div className={`p-3 rounded-lg ${vulnClass.lgpd.notificationRequired ? 'bg-red-100 border border-red-300' : 'bg-gray-100 border border-gray-200'}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Scale className={`w-4 h-4 ${vulnClass.lgpd.notificationRequired ? 'text-red-600' : 'text-gray-600'}`} />
              <span className={`text-sm font-medium ${vulnClass.lgpd.notificationRequired ? 'text-red-700' : 'text-gray-700'}`}>
                LGPD: {vulnClass.lgpd.articles.join(', ')}
              </span>
            </div>
            {vulnClass.lgpd.notificationRequired && (
              <div className="flex items-center gap-1 text-red-700">
                <Bell className="w-4 h-4" />
                <span className="text-xs font-semibold">Notificação ANPD Obrigatória</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Lista de VulnClasses
export function VulnClassList({ 
  vulnClasses, 
  onSelect,
  selectedClass,
}: { 
  vulnClasses: VulnClassCardProps['vulnClass'][]; 
  onSelect?: (vc: VulnClassCardProps['vulnClass']) => void;
  selectedClass?: string;
}) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {vulnClasses.map((vc) => (
        <div
          key={vc.class}
          className={`${selectedClass === vc.class ? 'ring-2 ring-primary-500 ring-offset-2' : ''} rounded-2xl`}
        >
          <VulnClassCard
            vulnClass={vc}
            onClick={onSelect ? () => onSelect(vc) : undefined}
          />
        </div>
      ))}
    </div>
  );
}
