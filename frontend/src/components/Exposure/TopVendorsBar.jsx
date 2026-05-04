'use client';

/**
 * Top vendors by exposure — horizontal bar chart with per-row
 * breakdown (critical / KEV / PoC / Nuclei). Bar width scales to
 * exposure_score (sum of priority of open findings).
 */
export default function TopVendorsBar({ vendors = [], loading, onSelectVendor }) {
  const max = Math.max(1, ...vendors.map((v) => Number(v.exposure_score) || 0));

  return (
    <section
      aria-label="Top vendors"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-white">Top vendor per esposizione</h3>
        <p className="text-xs text-gray-500">
          Pesato sulla somma di priority dei finding open
        </p>
      </header>
      {loading && vendors.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm">Caricamento…</div>
      ) : vendors.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm italic">
          Nessun vendor con finding open. Aggiungi prodotti o avvia una sync.
        </div>
      ) : (
        <ol className="divide-y divide-gray-800/50">
          {vendors.map((v) => {
            const score = Number(v.exposure_score) || 0;
            const widthPct = Math.round((score / max) * 100);
            return (
              <li key={v.vendor}>
                <button
                  type="button"
                  onClick={() => onSelectVendor?.(v.vendor)}
                  className="w-full text-left px-4 py-2 hover:bg-gray-800/60 focus:outline-none focus:bg-gray-800/80"
                >
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-gray-200 font-medium truncate min-w-[100px] max-w-[200px]">
                      {v.vendor}
                    </span>
                    <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                      <div
                        className="h-2 bg-indigo-500"
                        style={{ width: `${widthPct}%` }}
                        aria-hidden
                      />
                    </div>
                    <span className="font-mono text-gray-300 w-12 text-right">
                      {score}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-[11px] text-gray-500">
                    <span>{v.product_count} prodotti</span>
                    <span>{v.finding_count} finding</span>
                    {v.critical_count > 0 && (
                      <span className="text-red-300">{v.critical_count} critical</span>
                    )}
                    {v.kev_count > 0 && (
                      <span className="text-purple-300">{v.kev_count} KEV</span>
                    )}
                    {v.poc_count > 0 && (
                      <span className="text-emerald-300">{v.poc_count} PoC</span>
                    )}
                    {v.nuclei_count > 0 && (
                      <span className="text-fuchsia-300">{v.nuclei_count} Nuclei</span>
                    )}
                  </div>
                </button>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
