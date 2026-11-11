import React from 'react';

interface Point {
  label: string;
  value: number;
}

interface Props {
  data: Point[];
  height?: number;
  color?: string;
  formatLabel?: (label: string) => string;
}

// Lightweight dependency-free area chart. The console only needs a readable
// trend, so a single SVG keeps the bundle small and renders crisply.
const MiniChart: React.FC<Props> = ({ data, height = 190, color = '#5b5bd6', formatLabel }) => {
  const width = 720;
  const padX = 10;
  const padTop = 16;
  const padBottom = 26;
  const innerH = height - padTop - padBottom;
  const max = Math.max(1, ...data.map(d => d.value));
  const cell = data.length > 1 ? (width - padX * 2) / (data.length - 1) : 0;
  const points = data.map((d, i) => {
    const x = padX + i * cell;
    const y = padTop + innerH - (d.value / max) * innerH;
    return { ...d, x, y };
  });
  const line = points.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const area = points.length
    ? `${padX},${padTop + innerH} ${line} ${(padX + (data.length - 1) * cell).toFixed(1)},${padTop + innerH}`
    : '';
  const label = (v: string) => (formatLabel ? formatLabel(v) : v);
  const ticks = points.length > 4
    ? [0, Math.floor(points.length / 2), points.length - 1]
    : points.map((_, i) => i);

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width="100%"
      height={height}
      role="img"
      aria-label="请求趋势"
      style={{ display: 'block' }}
    >
      <defs>
        <linearGradient id="mini-chart-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.22" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {[0, 0.5, 1].map(f => (
        <line
          key={f}
          x1={padX}
          x2={width - padX}
          y1={padTop + innerH * f}
          y2={padTop + innerH * f}
          stroke="#eef2f7"
          strokeWidth="1"
        />
      ))}
      {area && <polygon points={area} fill="url(#mini-chart-fill)" />}
      {points.length > 1 && (
        <polyline points={line} fill="none" stroke={color} strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
      )}
      {points.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r={p.value > 0 ? 3 : 0} fill="#fff" stroke={color} strokeWidth="2">
          <title>{`${label(p.label)}：${p.value}`}</title>
        </circle>
      ))}
      {ticks.map(i => {
        const p = points[i];
        if (!p) return null;
        const anchor = i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle';
        return (
          <text key={i} x={p.x} y={height - 8} textAnchor={anchor} fontSize="11" fill="#94a3b8">
            {label(p.label)}
          </text>
        );
      })}
      <text x={padX} y={12} fontSize="11" fill="#94a3b8">
        峰值 {max}
      </text>
    </svg>
  );
};

export default MiniChart;
