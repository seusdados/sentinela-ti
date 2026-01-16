// ============================================================================
// SENTINELA - Componentes UI Reutilizáveis
// ============================================================================

import { clsx } from 'clsx';
import {
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  XCircle,
  Shield,
  ShieldAlert,
  Clock,
  RefreshCw,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Badge de Nível de Risco
// ---------------------------------------------------------------------------

type NivelRisco = 'CRITICO' | 'ALTO' | 'MEDIO' | 'BAIXO' | 'INFORMATIVO';

const CONFIG_RISCO: Record<NivelRisco, {
  label: string;
  className: string;
  icon: typeof AlertTriangle;
  descricao: string;
}> = {
  CRITICO: {
    label: 'Crítico',
    className: 'bg-red-100 text-red-800 border-red-200',
    icon: ShieldAlert,
    descricao: 'Requer ação imediata. Pode resultar em comprometimento severo.',
  },
  ALTO: {
    label: 'Alto',
    className: 'bg-orange-100 text-orange-800 border-orange-200',
    icon: AlertTriangle,
    descricao: 'Prioridade elevada. Deve ser tratado em até 24 horas.',
  },
  MEDIO: {
    label: 'Médio',
    className: 'bg-amber-100 text-amber-800 border-amber-200',
    icon: AlertCircle,
    descricao: 'Atenção necessária. Deve ser tratado em até 7 dias.',
  },
  BAIXO: {
    label: 'Baixo',
    className: 'bg-green-100 text-green-800 border-green-200',
    icon: CheckCircle,
    descricao: 'Risco menor. Pode ser tratado durante manutenção regular.',
  },
  INFORMATIVO: {
    label: 'Informativo',
    className: 'bg-blue-100 text-blue-800 border-blue-200',
    icon: Info,
    descricao: 'Para conhecimento. Não requer ação imediata.',
  },
};

interface BadgeRiscoProps {
  nivel: NivelRisco;
  showIcon?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function BadgeRisco({ nivel, showIcon = true, size = 'md', className }: BadgeRiscoProps) {
  const config = CONFIG_RISCO[nivel] || CONFIG_RISCO.INFORMATIVO;
  const Icon = config.icon;
  
  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3 py-1.5',
  };
  
  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-3.5 h-3.5',
    lg: 'w-4 h-4',
  };
  
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 font-medium rounded-full border',
        config.className,
        sizeClasses[size],
        className
      )}
      title={config.descricao}
    >
      {showIcon && <Icon className={iconSizes[size]} />}
      {config.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Badge de Status de Varredura
// ---------------------------------------------------------------------------

type StatusVarredura = 'AGUARDANDO' | 'EXECUTANDO' | 'CONCLUIDA' | 'FALHOU' | 'CANCELADA';

const CONFIG_STATUS: Record<StatusVarredura, {
  label: string;
  className: string;
  icon: typeof Clock;
}> = {
  AGUARDANDO: {
    label: 'Aguardando',
    className: 'bg-gray-100 text-gray-700',
    icon: Clock,
  },
  EXECUTANDO: {
    label: 'Em execução',
    className: 'bg-blue-100 text-blue-700',
    icon: RefreshCw,
  },
  CONCLUIDA: {
    label: 'Concluída',
    className: 'bg-green-100 text-green-700',
    icon: CheckCircle,
  },
  FALHOU: {
    label: 'Falhou',
    className: 'bg-red-100 text-red-700',
    icon: XCircle,
  },
  CANCELADA: {
    label: 'Cancelada',
    className: 'bg-gray-100 text-gray-500',
    icon: XCircle,
  },
};

interface BadgeStatusProps {
  status: StatusVarredura;
  showIcon?: boolean;
  className?: string;
}

export function BadgeStatus({ status, showIcon = true, className }: BadgeStatusProps) {
  const config = CONFIG_STATUS[status] || CONFIG_STATUS.AGUARDANDO;
  const Icon = config.icon;
  
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full',
        config.className,
        status === 'EXECUTANDO' && 'animate-pulse-slow',
        className
      )}
    >
      {showIcon && (
        <Icon className={clsx('w-3.5 h-3.5', status === 'EXECUTANDO' && 'animate-spin')} />
      )}
      {config.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Card de Métrica
// ---------------------------------------------------------------------------

interface MetricaCardProps {
  titulo: string;
  valor: number | string;
  descricao?: string;
  icon?: typeof Shield;
  cor?: 'blue' | 'green' | 'red' | 'orange' | 'purple';
  tendencia?: {
    valor: number;
    positivo: boolean;
  };
}

const CORES_METRICA = {
  blue: 'bg-blue-100 text-blue-600',
  green: 'bg-green-100 text-green-600',
  red: 'bg-red-100 text-red-600',
  orange: 'bg-orange-100 text-orange-600',
  purple: 'bg-purple-100 text-purple-600',
};

export function MetricaCard({ titulo, valor, descricao, icon: Icon, cor = 'blue', tendencia }: MetricaCardProps) {
  return (
    <div className="card">
      <div className="flex items-center gap-3 mb-3">
        {Icon && (
          <div className={clsx('w-10 h-10 rounded-xl flex items-center justify-center', CORES_METRICA[cor])}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      <div className="text-3xl font-bold text-gray-900">{valor}</div>
      <div className="text-sm text-gray-500 mt-1">{titulo}</div>
      {descricao && (
        <div className="text-xs text-gray-400 mt-2">{descricao}</div>
      )}
      {tendencia && (
        <div className={clsx(
          'text-xs font-medium mt-2',
          tendencia.positivo ? 'text-green-600' : 'text-red-600'
        )}>
          {tendencia.positivo ? '↑' : '↓'} {Math.abs(tendencia.valor)}% vs. período anterior
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading Spinner
// ---------------------------------------------------------------------------

interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function Spinner({ size = 'md', className }: SpinnerProps) {
  const sizes = {
    sm: 'w-4 h-4 border-2',
    md: 'w-8 h-8 border-2',
    lg: 'w-12 h-12 border-3',
  };
  
  return (
    <div
      className={clsx(
        'rounded-full border-primary-500 border-t-transparent animate-spin',
        sizes[size],
        className
      )}
    />
  );
}

// ---------------------------------------------------------------------------
// Empty State
// ---------------------------------------------------------------------------

interface EmptyStateProps {
  icon?: typeof Shield;
  titulo: string;
  descricao?: string;
  acao?: {
    label: string;
    onClick: () => void;
  };
}

export function EmptyState({ icon: Icon = Shield, titulo, descricao, acao }: EmptyStateProps) {
  return (
    <div className="text-center py-12">
      <Icon className="w-12 h-12 mx-auto text-gray-300 mb-4" />
      <h3 className="text-lg font-medium text-gray-900 mb-1">{titulo}</h3>
      {descricao && <p className="text-gray-500">{descricao}</p>}
      {acao && (
        <button onClick={acao.onClick} className="btn btn-primary mt-4">
          {acao.label}
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeleton Loading
// ---------------------------------------------------------------------------

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className }: SkeletonProps) {
  return <div className={clsx('skeleton', className)} />;
}

export function SkeletonCard() {
  return (
    <div className="card">
      <Skeleton className="h-6 w-32 mb-3" />
      <Skeleton className="h-8 w-20 mb-2" />
      <Skeleton className="h-4 w-full" />
    </div>
  );
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          <Skeleton className="h-10 w-10 rounded-lg" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-1/2" />
          </div>
        </div>
      ))}
    </div>
  );
}
