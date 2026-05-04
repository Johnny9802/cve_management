'use client';

/**
 * Headline KPI tile with trend arrow + sparkline. The sparkline uses
 * inline SVG to keep the bundle slim (no recharts for a 60-pixel
 * widget).
 */
function trendCls(delta, kind) {
  if (delta == null) return 'text-gray-500';
  const positiveIsBad = kind !== 'velocity';
  if (delta === 0) return 'text-gray-400';
  const isWorse = positiveIsBad ? delta > 0 : delta < 0;
  return isWorse ? 'text-red-300' : 'text-green-300';
}

function trendArrow(delta) {
  if (delta == null || delta === 0) return '·';
  return delta > 0 ? '↑' : '↓';
}

function Sparkline({ values, width = 110, height = 28, kind = 'risk' }) {
  if (!values || values.length === 0) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const stepX = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((v, i) => {
      const x = i * stepX;
      const y = height - ((v - min) / range) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
  const stroke = kind === 'velocity' ? '#34d399' : '#818cf8';
  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden
      className="opacity-70"
    >
      <polyline
        points={points}
        fill="none"
        stroke={stroke}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function KpiTrendCard({ label, value, sub, delta, kind, sparkline }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex flex-col gap-1">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="flex items-end gap-2 flex-wrap">
        <div className="text-2xl font-bold text-white">{value ?? '—'}</div>
        {delta != null && (
          <span className={`text-xs font-mono ${trendCls(delta, kind)}`}>
            {trendArrow(delta)} {Math.abs(delta)}
          </span>
        )}
      </div>
      {sub && <div className="text-[11px] text-gray-500">{sub}</div>}
      {sparkline && sparkline.length > 1 && (
        <div className="mt-1">
          <Sparkline values={sparkline} kind={kind} />
        </div>
      )}
    </div>
  );
}
