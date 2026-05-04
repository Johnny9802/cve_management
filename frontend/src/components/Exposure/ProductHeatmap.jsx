'use client';

/**
 * CSS-grid heatmap: rows = top products, columns = severity buckets +
 * KEV. Cell shading scales to absolute count. Click a cell → selects
 * the product (caller can drill down to product detail / SOC Triage).
 *
 * Intentional choice: pure CSS (no d3 / vega) so the bundle stays
 * slim and a11y is preserved.
 */
// rgba() triplets — Tailwind 900 shades for each column.
const COLS = [
  { key: 'critical', label: 'CRIT', accent: 'text-red-300',    rgb: '127, 29, 29'   },
  { key: 'high',     label: 'HIGH', accent: 'text-orange-300', rgb: '124, 45, 18'   },
  { key: 'medium',   label: 'MED',  accent: 'text-yellow-300', rgb: '113, 63, 18'   },
  { key: 'low',      label: 'LOW',  accent: 'text-blue-300',   rgb: '30, 58, 138'   },
  { key: 'kev',      label: 'KEV',  accent: 'text-purple-300', rgb: '88, 28, 135'   },
];

export default function ProductHeatmap({ heatmap = [], loading, onSelectProduct }) {
  // Per-column max for proportional shading.
  const max = Object.fromEntries(
    COLS.map((c) => [c.key, Math.max(1, ...heatmap.map((r) => Number(r[c.key]) || 0))])
  );

  return (
    <section
      aria-label="Heatmap prodotti"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-white">Heatmap esposizione per prodotto</h3>
        <p className="text-xs text-gray-500">
          Intensità del colore = count di finding nella cella. Click → dettaglio prodotto.
        </p>
      </header>
      {loading && heatmap.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm">Caricamento…</div>
      ) : heatmap.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm italic">
          Nessun prodotto in inventario.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-500">
                <th className="text-left px-3 py-1.5 font-medium">Prodotto</th>
                {COLS.map((c) => (
                  <th key={c.key} className="text-center px-2 py-1.5 font-medium">{c.label}</th>
                ))}
                <th className="text-right px-3 py-1.5 font-medium">Tot</th>
                <th className="text-right px-3 py-1.5 font-medium">Avg priority</th>
              </tr>
            </thead>
            <tbody>
              {heatmap.map((row) => (
                <tr key={row.id} className="border-t border-gray-800">
                  <td className="px-3 py-1.5">
                    <button
                      type="button"
                      onClick={() => onSelectProduct?.(row)}
                      className="text-left text-gray-100 hover:text-indigo-300 focus:outline-none focus:underline"
                    >
                      <div className="font-medium truncate max-w-[220px]">{row.name}</div>
                      <div className="text-[10px] text-gray-500 truncate max-w-[220px]">
                        {row.version}{row.vendor ? ` · ${row.vendor}` : ''}
                      </div>
                    </button>
                  </td>
                  {COLS.map((c) => {
                    const v = Number(row[c.key]) || 0;
                    const intensity = v === 0 ? 0 : Math.min(100, Math.round((v / max[c.key]) * 100));
                    const opacity = v === 0 ? 0 : 0.2 + (intensity / 100) * 0.7;
                    return (
                      <td key={c.key} className="px-2 py-1.5 text-center">
                        <span
                          className={`inline-block min-w-[2rem] px-1.5 py-0.5 rounded ${c.accent} font-mono`}
                          style={v === 0
                            ? { background: 'transparent' }
                            : { backgroundColor: `rgba(${c.rgb}, ${opacity})` }}
                          title={v ? `${c.label}: ${v} finding` : undefined}
                        >
                          {v || '·'}
                        </span>
                      </td>
                    );
                  })}
                  <td className="px-3 py-1.5 text-right font-mono text-gray-200">
                    {row.total}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-gray-300">
                    {row.avg_priority ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

