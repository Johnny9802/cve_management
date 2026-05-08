'use client';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';

/**
 * Stacked bar timeline of CVE publications. Pass `onBarClick(monthKey)`
 * to make bars interactive; the active bar's label is prefixed with ▸.
 *
 * Sprint 2 / S2.6 (FE-05).
 */
export default function TimelineChart({ data = [], onBarClick, activeMonth }) {
  if (!data.length) return null;

  const interactive = typeof onBarClick === 'function';
  const handleClick = (barData) => {
    if (!interactive || !barData) return;
    onBarClick(barData.activeLabel || barData.month || null);
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3">
        CVE pubblicati — ultimi 12 mesi
        {interactive && (
          <span className="text-[10px] font-normal text-gray-500 ml-2">
            (click su una barra per filtrare)
          </span>
        )}
      </h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart
          data={data}
          margin={{ top: 0, right: 0, left: -20, bottom: 0 }}
          onClick={handleClick}
          style={{ cursor: interactive ? 'pointer' : 'default' }}
        >
          <XAxis
            dataKey="month"
            tick={{ fontSize: 10, fill: '#9ca3af' }}
            tickFormatter={(m) => (activeMonth === m ? `▸ ${m}` : m)}
          />
          <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} />
          <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }} />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          <Bar dataKey="critical" name="Critical" fill="#ef4444" stackId="a" />
          <Bar dataKey="high" name="High" fill="#f97316" stackId="a" />
          <Bar dataKey="kev" name="CISA KEV" fill="#a855f7" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
