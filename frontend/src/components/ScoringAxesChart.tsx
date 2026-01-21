// ============================================================================
// SENTINELA - Componente de Visualização de Scoring 5 Eixos
// Exibe os 5 eixos de scoring em formato radar/barras
// ============================================================================

import { useMemo } from 'react';
import {
  Eye,
  Zap,
  Database,
  Users,
  Target,
  AlertTriangle,
  AlertOctagon,
  Shield,
  ShieldCheck,
} from 'lucide-react';

interface ScoreAxes {
  exposure: number;
  exploitability: number;
  dataSensitivity: number;
  scale: number;
  confidence: number;
}

interface ScoringAxesChartProps {
  axes: ScoreAxes;
  scoreFinal: number;
  riskLevel?: string;
  showLabels?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

const EIXOS_INFO = {
  exposure: {
    nome: 'Exposição',
    descricao: 'Quão exposto está (público vs interno)',
    peso: '25%',
    icone: Eye,
    cor: '#3B82F6', // blue
  },
  exploitability: {
    nome: 'Explorabilidade',
    descricao: 'Facilidade de exploração',
    peso: '25%',
    icone: Zap,
    cor: '#F59E0B', // amber
  },
  dataSensitivity: {
    nome: 'Sensibilidade',
    descricao: 'Sensibilidade dos dados (PII, financeiro, etc)',
    peso: '20%',
    icone: Database,
    cor: '#EF4444', // red
  },
  scale: {
    nome: 'Escala',
    descricao: 'Quantidade de registros/usuários afetados',
    peso: '15%',
    icone: Users,
    cor: '#8B5CF6', // violet
  },
  confidence: {
    nome: 'Confiança',
    descricao: 'Confiança na detecção',
    peso: '15%',
    icone: Target,
    cor: '#10B981', // emerald
  },
};

const CLASSIFICACOES = {
  CRITICO: { cor: '#DC2626', corBg: '#FEF2F2', icone: AlertOctagon, label: 'Crítico' },
  ALTO: { cor: '#EA580C', corBg: '#FFF7ED', icone: AlertTriangle, label: 'Alto' },
  MEDIO: { cor: '#D97706', corBg: '#FFFBEB', icone: Shield, label: 'Médio' },
  BAIXO: { cor: '#16A34A', corBg: '#F0FDF4', icone: ShieldCheck, label: 'Baixo' },
};

export default function ScoringAxesChart({
  axes,
  scoreFinal,
  riskLevel = 'MEDIO',
  showLabels = true,
  size = 'md',
}: ScoringAxesChartProps) {
  const config = CLASSIFICACOES[riskLevel as keyof typeof CLASSIFICACOES] || CLASSIFICACOES.MEDIO;
  const IconeRisco = config.icone;

  const tamanhos = {
    sm: { barHeight: 'h-2', fontSize: 'text-xs', gap: 'gap-2' },
    md: { barHeight: 'h-3', fontSize: 'text-sm', gap: 'gap-3' },
    lg: { barHeight: 'h-4', fontSize: 'text-base', gap: 'gap-4' },
  };

  const t = tamanhos[size];

  return (
    <div className="space-y-4">
      {/* Score Final */}
      <div className="flex items-center justify-between p-4 rounded-xl" style={{ backgroundColor: config.corBg }}>
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: config.cor + '20' }}>
            <IconeRisco className="w-6 h-6" style={{ color: config.cor }} />
          </div>
          <div>
            <p className="text-sm text-gray-600">Score de Risco</p>
            <p className="text-2xl font-bold" style={{ color: config.cor }}>{scoreFinal}/100</p>
          </div>
        </div>
        <div className="text-right">
          <span 
            className="px-3 py-1 rounded-full text-sm font-semibold"
            style={{ backgroundColor: config.cor, color: 'white' }}
          >
            {config.label}
          </span>
        </div>
      </div>

      {/* Eixos */}
      <div className={`space-y-${size === 'sm' ? '2' : '3'}`}>
        {Object.entries(axes).map(([key, value]) => {
          const info = EIXOS_INFO[key as keyof typeof EIXOS_INFO];
          const Icone = info.icone;

          return (
            <div key={key} className={t.gap}>
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <Icone className="w-4 h-4" style={{ color: info.cor }} />
                  <span className={`font-medium text-gray-700 ${t.fontSize}`}>{info.nome}</span>
                  <span className="text-xs text-gray-400">({info.peso})</span>
                </div>
                <span className={`font-semibold ${t.fontSize}`} style={{ color: info.cor }}>
                  {value}%
                </span>
              </div>
              <div className={`w-full bg-gray-200 rounded-full ${t.barHeight}`}>
                <div
                  className={`${t.barHeight} rounded-full transition-all duration-500`}
                  style={{ width: `${value}%`, backgroundColor: info.cor }}
                />
              </div>
              {showLabels && (
                <p className="text-xs text-gray-500 mt-0.5">{info.descricao}</p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Versão compacta para cards
export function ScoringAxesMini({ axes, scoreFinal, riskLevel = 'MEDIO' }: { axes: ScoreAxes; scoreFinal: number; riskLevel?: string }) {
  const config = CLASSIFICACOES[riskLevel as keyof typeof CLASSIFICACOES] || CLASSIFICACOES.MEDIO;

  return (
    <div className="flex items-center gap-4">
      <div 
        className="w-14 h-14 rounded-xl flex items-center justify-center"
        style={{ backgroundColor: config.corBg }}
      >
        <span className="text-xl font-bold" style={{ color: config.cor }}>{scoreFinal}</span>
      </div>
      <div className="flex-1 space-y-1">
        {Object.entries(axes).slice(0, 3).map(([key, value]) => {
          const info = EIXOS_INFO[key as keyof typeof EIXOS_INFO];
          return (
            <div key={key} className="flex items-center gap-2">
              <span className="text-xs text-gray-500 w-16 truncate">{info.nome}</span>
              <div className="flex-1 h-1.5 bg-gray-200 rounded-full">
                <div
                  className="h-1.5 rounded-full"
                  style={{ width: `${value}%`, backgroundColor: info.cor }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Radar Chart (visualização alternativa)
export function ScoringRadarChart({ axes, size = 200 }: { axes: ScoreAxes; size?: number }) {
  const center = size / 2;
  const radius = (size / 2) - 30;
  const eixos = Object.entries(axes);
  const numEixos = eixos.length;
  const angleStep = (2 * Math.PI) / numEixos;

  // Calcular pontos do polígono
  const pontos = eixos.map(([_, value], i) => {
    const angle = i * angleStep - Math.PI / 2;
    const r = (value / 100) * radius;
    return {
      x: center + r * Math.cos(angle),
      y: center + r * Math.sin(angle),
    };
  });

  const pontosStr = pontos.map(p => `${p.x},${p.y}`).join(' ');

  // Pontos para o grid de fundo
  const gridLevels = [25, 50, 75, 100];

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {/* Grid de fundo */}
      {gridLevels.map(level => {
        const r = (level / 100) * radius;
        const gridPontos = eixos.map((_, i) => {
          const angle = i * angleStep - Math.PI / 2;
          return `${center + r * Math.cos(angle)},${center + r * Math.sin(angle)}`;
        }).join(' ');
        return (
          <polygon
            key={level}
            points={gridPontos}
            fill="none"
            stroke="#E5E7EB"
            strokeWidth="1"
          />
        );
      })}

      {/* Linhas dos eixos */}
      {eixos.map((_, i) => {
        const angle = i * angleStep - Math.PI / 2;
        return (
          <line
            key={i}
            x1={center}
            y1={center}
            x2={center + radius * Math.cos(angle)}
            y2={center + radius * Math.sin(angle)}
            stroke="#E5E7EB"
            strokeWidth="1"
          />
        );
      })}

      {/* Área preenchida */}
      <polygon
        points={pontosStr}
        fill="rgba(59, 130, 246, 0.2)"
        stroke="#3B82F6"
        strokeWidth="2"
      />

      {/* Pontos nos vértices */}
      {pontos.map((p, i) => (
        <circle
          key={i}
          cx={p.x}
          cy={p.y}
          r="4"
          fill="#3B82F6"
        />
      ))}

      {/* Labels */}
      {eixos.map(([key], i) => {
        const angle = i * angleStep - Math.PI / 2;
        const labelRadius = radius + 20;
        const x = center + labelRadius * Math.cos(angle);
        const y = center + labelRadius * Math.sin(angle);
        const info = EIXOS_INFO[key as keyof typeof EIXOS_INFO];
        return (
          <text
            key={key}
            x={x}
            y={y}
            textAnchor="middle"
            dominantBaseline="middle"
            className="text-xs fill-gray-600"
          >
            {info.nome}
          </text>
        );
      })}
    </svg>
  );
}
