// ============================================================================
// SENTINELA - Componente de Score de Risco (Gauge Visual)
// Exibe o score de risco de forma visual e intuitiva
// ============================================================================

import { useMemo } from 'react';
import { ShieldCheck, ShieldAlert, Shield, AlertTriangle, AlertOctagon } from 'lucide-react';

interface RiskScoreGaugeProps {
  score: number;
  classificacao?: string;
  tamanho?: 'sm' | 'md' | 'lg';
  mostrarDetalhes?: boolean;
}

const CLASSIFICACOES = {
  CRITICO: {
    cor: '#dc2626',
    corBg: '#fef2f2',
    corBorda: '#fecaca',
    icone: AlertOctagon,
    label: 'Crítico',
    descricao: 'Risco crítico detectado. Ação imediata necessária.',
  },
  ALTO: {
    cor: '#ea580c',
    corBg: '#fff7ed',
    corBorda: '#fed7aa',
    icone: AlertTriangle,
    label: 'Alto',
    descricao: 'Risco alto identificado. Priorize a remediação.',
  },
  MEDIO: {
    cor: '#d97706',
    corBg: '#fffbeb',
    corBorda: '#fde68a',
    icone: Shield,
    label: 'Médio',
    descricao: 'Risco moderado. Planeje ações de mitigação.',
  },
  BAIXO: {
    cor: '#16a34a',
    corBg: '#f0fdf4',
    corBorda: '#bbf7d0',
    icone: ShieldCheck,
    label: 'Baixo',
    descricao: 'Risco baixo. Continue monitorando.',
  },
  MINIMO: {
    cor: '#0ea5e9',
    corBg: '#f0f9ff',
    corBorda: '#bae6fd',
    icone: ShieldCheck,
    label: 'Mínimo',
    descricao: 'Postura de segurança saudável.',
  },
};

export default function RiskScoreGauge({ 
  score, 
  classificacao,
  tamanho = 'md',
  mostrarDetalhes = true,
}: RiskScoreGaugeProps) {
  const config = useMemo(() => {
    // Determinar classificação baseada no score se não fornecida
    let classif = classificacao?.toUpperCase() || 'MINIMO';
    if (!classificacao) {
      if (score >= 80) classif = 'CRITICO';
      else if (score >= 60) classif = 'ALTO';
      else if (score >= 40) classif = 'MEDIO';
      else if (score >= 20) classif = 'BAIXO';
      else classif = 'MINIMO';
    }
    return CLASSIFICACOES[classif as keyof typeof CLASSIFICACOES] || CLASSIFICACOES.MINIMO;
  }, [score, classificacao]);

  const tamanhos = {
    sm: { container: 'w-24 h-24', texto: 'text-xl', label: 'text-xs' },
    md: { container: 'w-36 h-36', texto: 'text-3xl', label: 'text-sm' },
    lg: { container: 'w-48 h-48', texto: 'text-4xl', label: 'text-base' },
  };

  const t = tamanhos[tamanho];
  const Icone = config.icone;

  // Calcular ângulo para o arco do gauge (180 graus = semicírculo)
  const angulo = (score / 100) * 180;
  const raio = tamanho === 'sm' ? 40 : tamanho === 'md' ? 60 : 80;
  const strokeWidth = tamanho === 'sm' ? 6 : tamanho === 'md' ? 8 : 10;
  const centro = raio + strokeWidth;
  const tamanhoSvg = (raio + strokeWidth) * 2;

  // Calcular coordenadas do arco
  const calcularPontoArco = (anguloDeg: number) => {
    const anguloRad = ((180 - anguloDeg) * Math.PI) / 180;
    return {
      x: centro + raio * Math.cos(anguloRad),
      y: centro - raio * Math.sin(anguloRad),
    };
  };

  const pontoInicio = calcularPontoArco(0);
  const pontoFim = calcularPontoArco(angulo);
  const largeArcFlag = angulo > 90 ? 1 : 0;

  const pathArco = `M ${pontoInicio.x} ${pontoInicio.y} A ${raio} ${raio} 0 ${largeArcFlag} 1 ${pontoFim.x} ${pontoFim.y}`;
  const pathFundo = `M ${pontoInicio.x} ${pontoInicio.y} A ${raio} ${raio} 0 1 1 ${calcularPontoArco(180).x} ${calcularPontoArco(180).y}`;

  return (
    <div className="flex flex-col items-center">
      {/* Gauge SVG */}
      <div className="relative">
        <svg width={tamanhoSvg} height={centro + 10} viewBox={`0 0 ${tamanhoSvg} ${centro + 10}`}>
          {/* Arco de fundo */}
          <path
            d={pathFundo}
            fill="none"
            stroke="#e5e7eb"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Arco de progresso */}
          {score > 0 && (
            <path
              d={pathArco}
              fill="none"
              stroke={config.cor}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              style={{
                transition: 'stroke-dashoffset 0.5s ease-in-out',
              }}
            />
          )}
        </svg>
        
        {/* Score no centro */}
        <div 
          className="absolute inset-0 flex flex-col items-center justify-center"
          style={{ paddingTop: tamanho === 'sm' ? '8px' : tamanho === 'md' ? '16px' : '24px' }}
        >
          <span className={`font-bold ${t.texto}`} style={{ color: config.cor }}>
            {score}
          </span>
          <span className={`text-gray-500 ${t.label}`}>de 100</span>
        </div>
      </div>

      {/* Label e ícone */}
      <div 
        className="flex items-center gap-2 mt-2 px-3 py-1.5 rounded-full"
        style={{ backgroundColor: config.corBg, border: `1px solid ${config.corBorda}` }}
      >
        <Icone className="w-4 h-4" style={{ color: config.cor }} />
        <span className="font-semibold text-sm" style={{ color: config.cor }}>
          Risco {config.label}
        </span>
      </div>

      {/* Descrição */}
      {mostrarDetalhes && (
        <p className="text-xs text-gray-500 text-center mt-2 max-w-[200px]">
          {config.descricao}
        </p>
      )}
    </div>
  );
}

// Componente de barra de progresso horizontal (alternativa)
export function RiskScoreBar({ score, classificacao }: { score: number; classificacao?: string }) {
  const config = useMemo(() => {
    let classif = classificacao?.toUpperCase() || 'MINIMO';
    if (!classificacao) {
      if (score >= 80) classif = 'CRITICO';
      else if (score >= 60) classif = 'ALTO';
      else if (score >= 40) classif = 'MEDIO';
      else if (score >= 20) classif = 'BAIXO';
      else classif = 'MINIMO';
    }
    return CLASSIFICACOES[classif as keyof typeof CLASSIFICACOES] || CLASSIFICACOES.MINIMO;
  }, [score, classificacao]);

  const Icone = config.icone;

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Icone className="w-5 h-5" style={{ color: config.cor }} />
          <span className="font-semibold" style={{ color: config.cor }}>
            Risco {config.label}
          </span>
        </div>
        <span className="text-2xl font-bold" style={{ color: config.cor }}>
          {score}/100
        </span>
      </div>
      
      <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ 
            width: `${score}%`,
            backgroundColor: config.cor,
          }}
        />
      </div>
      
      {/* Marcadores */}
      <div className="flex justify-between mt-1 text-xs text-gray-400">
        <span>0</span>
        <span>20</span>
        <span>40</span>
        <span>60</span>
        <span>80</span>
        <span>100</span>
      </div>
    </div>
  );
}
