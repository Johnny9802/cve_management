'use client';

/**
 * Multi-series line chart over the exec_snapshots series. Reuses
 * recharts (already bundled). Defaults to two series: open critical
 * (red) and KEV-with-open-finding (purple). Pass `series` to override.
 */
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, CartesianGrid } from 'recharts';

const DEFAULT_SERIES = [
  { dataKey: 'critical_open',         name: 'Critical open',  color: '#ef4444' },
  { dataKey: 'kev_with_open_finding', name: 'KEV finding',    color: '#a855f7' },
  { dataKey: 'findings_breached',     name: 'SLA breached',   color: '#f97316' },
];

export default function TrendLineChart({ data = [], series = DEFAULT_SERIES, title, hint }) {
  return (
    <section
      aria-label={title || 'Trend'}
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      {(title || hint) && (
        <header className="px-4 py-2.5 border-b border-gray-800">
          {title && <h3 className="text-sm font-semibold text-white">{title}</h3>}
          {hint && <p className="text-xs text-gray-500">{hint}</p>}
        </header>
      )}
      <div className="p-3">
        {data.length < 2 ? (
          <div className="py-8 text-center text-gray-500 text-sm italic">
            {data.length === 0
              ? 'Nessuno snapshot disponibile.'
              : 'Trend disponibile dopo 2+ giorni di snapshot — il job daily_snapshot ne cattura uno al giorno alle 00:05 UTC.'}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis
                dataKey="captured_on"
                tick={{ fontSize: 10, fill: '#9ca3af' }}
                tickFormatter={(v) => (v || '').slice(5)}
              />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#e5e7eb' }}
              />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {series.map((s) => (
                <Line
                  key={s.dataKey}
                  type="monotone"
                  dataKey={s.dataKey}
                  name={s.name}
                  stroke={s.color}
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4 }}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}
