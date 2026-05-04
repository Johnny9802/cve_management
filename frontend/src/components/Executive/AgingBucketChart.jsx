'use client';

/**
 * Stacked-bar of open-finding aging: 0-30 / 30-90 / 90+ days. The
 * 90+ bucket is the worry signal — the longer a finding stays open,
 * the more likely it is structurally blocked.
 */
const BUCKETS = [
  { key: 'bucket_0_30',   label: '0-30 gg',   color: 'bg-green-700/70'  },
  { key: 'bucket_30_90',  label: '30-90 gg',  color: 'bg-amber-700/70'  },
  { key: 'bucket_90_plus', label: '90+ gg',    color: 'bg-red-700/80'    },
];

export default function AgingBucketChart({ buckets = {}, loading }) {
  const total = (buckets.bucket_0_30 || 0)
    + (buckets.bucket_30_90 || 0)
    + (buckets.bucket_90_plus || 0);

  return (
    <section
      aria-label="Aging dei finding open"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-white">Aging dei finding open</h3>
        <p className="text-xs text-gray-500">
          Quanto sono &laquo;vecchi&raquo; i finding ancora aperti — il bucket 90+ è il segnale critico
        </p>
      </header>
      <div className="p-4">
        {loading ? (
          <div className="text-xs text-gray-500 text-center py-4">Caricamento…</div>
        ) : total === 0 ? (
          <div className="text-xs text-gray-500 text-center py-4 italic">
            Nessun finding aperto.
          </div>
        ) : (
          <>
            <div className="flex h-6 rounded overflow-hidden bg-gray-800" aria-hidden>
              {BUCKETS.map((b) => {
                const v = buckets[b.key] || 0;
                if (!v) return null;
                const pct = (v / total) * 100;
                return (
                  <div
                    key={b.key}
                    className={`h-6 ${b.color} flex items-center justify-center text-[10px] text-white font-mono`}
                    style={{ width: `${pct}%` }}
                    title={`${b.label}: ${v} finding`}
                  >
                    {pct >= 12 ? v : ''}
                  </div>
                );
              })}
            </div>
            <div className="grid grid-cols-3 gap-2 mt-3">
              {BUCKETS.map((b) => (
                <div key={b.key} className="text-xs">
                  <div className="flex items-center gap-1.5">
                    <span aria-hidden className={`inline-block w-2.5 h-2.5 rounded-sm ${b.color}`} />
                    <span className="text-gray-500">{b.label}</span>
                  </div>
                  <div className="text-base font-bold text-white mt-0.5">
                    {buckets[b.key] || 0}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </section>
  );
}
