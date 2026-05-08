'use client';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', NONE: '#6b7280' };

/**
 * Severity pie chart. Pass `onSliceClick(severity)` to make slices
 * interactive — they then act as filter chips and the active slice is
 * outlined in white. Sprint 2 / S2.6 fixes FE-05.
 */
export default function SeverityChart({ data = [], onSliceClick, activeSeverity }) {
  const chartData = data
    .filter((d) => parseInt(d.count) > 0)
    .map((d) => ({ name: d.severity || 'NONE', value: parseInt(d.count) }));

  if (!chartData.length) return null;

  const interactive = typeof onSliceClick === 'function';

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3">
        Distribuzione per Severità
        {interactive && (
          <span className="text-[10px] font-normal text-gray-500 ml-2">
            (click su una fetta per filtrare)
          </span>
        )}
      </h3>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={chartData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={80}
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
            labelLine={false}
            isAnimationActive={false}
            onClick={(slice) => interactive && onSliceClick(slice?.name || null)}
            cursor={interactive ? 'pointer' : 'default'}
          >
            {chartData.map((entry) => (
              <Cell
                key={entry.name}
                fill={COLORS[entry.name] || '#6b7280'}
                stroke={activeSeverity === entry.name ? '#ffffff' : 'none'}
                strokeWidth={activeSeverity === entry.name ? 2 : 0}
                opacity={activeSeverity && activeSeverity !== entry.name ? 0.4 : 1}
              />
            ))}
          </Pie>
          <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
