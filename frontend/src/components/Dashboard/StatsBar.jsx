'use client';

/**
 * Static KPI strip. Tiles are NOT interactive (no hover background, no
 * cursor-pointer) so they don't suggest a click affordance they cannot
 * honour. Sprint Frontend 2 will replace this with a clickable variant
 * that filters the CVE list — until then they stay informational only.
 */
export default function StatsBar({ stats }) {
  if (!stats) return null;

  const severity = Object.fromEntries(
    (stats.severity || []).map((s) => [s.severity, parseInt(s.count)])
  );

  const cards = [
    { label: 'Prodotti monitorati', value: stats.product_count,                       accent: 'text-indigo-400' },
    { label: 'CVE totali',          value: stats.total_cves?.toLocaleString(),         accent: 'text-gray-200' },
    { label: 'Critical',            value: severity['CRITICAL']?.toLocaleString() || 0, accent: 'text-red-400' },
    { label: 'High',                value: severity['HIGH']?.toLocaleString() || 0,    accent: 'text-orange-400' },
    { label: 'In CISA KEV',         value: stats.kev_count?.toLocaleString(),          accent: 'text-purple-400' },
    {
      label: 'Priorità Critica',
      value: parseInt(stats.priority_distribution?.critical_priority || 0).toLocaleString(),
      accent: 'text-rose-400',
    },
  ];

  return (
    <dl className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6" aria-label="Indicatori sintetici">
      {cards.map((c) => (
        <div
          key={c.label}
          className="rounded-xl bg-gray-900 border border-gray-800 p-4"
        >
          <dt className="text-xs text-gray-500 mb-1">{c.label}</dt>
          <dd className={`text-2xl font-bold ${c.accent}`}>{c.value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  );
}
