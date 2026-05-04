'use client';

/**
 * Inventory data-quality strip — surfaces the % of products with
 * resolved CPE, syncing state, and stale-sync count. Spotting
 * unresolved CPEs is the single highest-leverage action to improve
 * inventory exposure visibility.
 */
function pct(n, d) {
  if (!d) return 0;
  return Math.round((n / d) * 100);
}

export default function InventoryCoverageStrip({ coverage = {}, loading }) {
  const total = coverage.total || 0;
  const resolved = coverage.resolved || 0;
  const certain = coverage.confidence_certain || 0;
  const synced = coverage.synced || 0;
  const stale = coverage.sync_stale || 0;
  const errors = coverage.sync_error || 0;

  const cells = [
    {
      label: 'Prodotti totali',
      value: total,
      sub: 'in inventario',
      color: 'text-gray-200',
    },
    {
      label: 'CPE risolti',
      value: total ? `${pct(resolved, total)}%` : '—',
      sub: `${resolved} / ${total}`,
      color: pct(resolved, total) >= 80 ? 'text-green-300' : 'text-amber-300',
    },
    {
      label: 'Confidence: certain',
      value: total ? `${pct(certain, total)}%` : '—',
      sub: `${certain} / ${total}`,
      color: 'text-indigo-300',
    },
    {
      label: 'Sync OK',
      value: total ? `${pct(synced, total)}%` : '—',
      sub: `${synced} / ${total}`,
      color: pct(synced, total) >= 80 ? 'text-green-300' : 'text-gray-300',
    },
    {
      label: 'Sync stale (>7gg)',
      value: stale,
      sub: 'da resincronizzare',
      color: stale > 0 ? 'text-amber-300' : 'text-gray-500',
    },
    {
      label: 'Sync error',
      value: errors,
      sub: 'da risolvere',
      color: errors > 0 ? 'text-red-300' : 'text-gray-500',
    },
  ];

  return (
    <section
      aria-label="Copertura inventario"
      className="bg-gray-900 border border-gray-800 rounded-xl p-3"
    >
      <header className="mb-2">
        <h3 className="text-sm font-semibold text-white">Copertura inventario</h3>
        <p className="text-xs text-gray-500">
          La risoluzione CPE e la freschezza della sync sono i predittori più forti dell&apos;esposizione reale.
        </p>
      </header>
      <dl className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
        {cells.map((c) => (
          <div key={c.label} className="bg-gray-950/50 border border-gray-800 rounded p-2">
            <dt className="text-[10px] uppercase text-gray-500">{c.label}</dt>
            <dd className={`text-lg font-bold ${c.color}`}>
              {loading ? '…' : c.value}
            </dd>
            <div className="text-[10px] text-gray-600">{c.sub}</div>
          </div>
        ))}
      </dl>
    </section>
  );
}
