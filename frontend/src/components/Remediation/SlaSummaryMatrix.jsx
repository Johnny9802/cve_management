'use client';

/**
 * Reads /api/findings/sla/summary and renders a severity × state matrix
 * with absolute counts. KEV breached count gets its own callout because
 * KEV with breach is the most severe operational signal.
 */
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATES = [
  { key: 'breached', label: 'Breached', cls: 'bg-red-900/30 text-red-300 border-red-800' },
  { key: 'at_risk',  label: 'At risk',  cls: 'bg-amber-900/30 text-amber-300 border-amber-800' },
  { key: 'on_track', label: 'On track', cls: 'bg-gray-800 text-gray-300 border-gray-700' },
  { key: 'met',      label: 'Met',      cls: 'bg-green-900/30 text-green-300 border-green-800' },
];

export default function SlaSummaryMatrix({ summary, mttr, loading }) {
  const matrix = summary?.by_severity || {};
  const totals = summary?.totals || {};
  const kevBreached = summary?.kev_breached ?? 0;

  return (
    <section
      aria-label="SLA summary"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800 flex items-center justify-between flex-wrap gap-2">
        <div>
          <h3 className="text-sm font-semibold text-white">SLA compliance</h3>
          <p className="text-xs text-gray-500">
            Default: CRITICAL 7gg · HIGH 30gg · MEDIUM 90gg · LOW 180gg · KEV override 3gg
          </p>
        </div>
        {kevBreached > 0 && (
          <span className="bg-red-900/40 border border-red-700 text-red-300 px-2 py-0.5 rounded text-xs font-medium">
            ⚠ {kevBreached} KEV breached
          </span>
        )}
      </header>

      <div className="p-3">
        {loading && !summary ? (
          <div className="text-xs text-gray-500 text-center py-6">Caricamento…</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-500">
                  <th className="text-left px-2 py-1.5 font-medium">Severità</th>
                  {STATES.map((s) => (
                    <th key={s.key} className="text-right px-2 py-1.5 font-medium">{s.label}</th>
                  ))}
                  <th className="text-right px-2 py-1.5 font-medium">Totale</th>
                </tr>
              </thead>
              <tbody>
                {SEVERITIES.map((sev) => {
                  const row = matrix[sev] || {};
                  const total = STATES.reduce((sum, s) => sum + (row[s.key] || 0), 0);
                  if (total === 0) return null;
                  return (
                    <tr key={sev} className="border-t border-gray-800">
                      <td className="px-2 py-1.5 font-medium text-gray-200">{sev}</td>
                      {STATES.map((s) => (
                        <td key={s.key} className="px-2 py-1.5 text-right">
                          <span className={`inline-block min-w-[2rem] px-1.5 py-0.5 rounded border font-mono ${s.cls}`}>
                            {row[s.key] || 0}
                          </span>
                        </td>
                      ))}
                      <td className="px-2 py-1.5 text-right font-mono text-gray-300">{total}</td>
                    </tr>
                  );
                })}
                <tr className="border-t border-gray-700 font-semibold">
                  <td className="px-2 py-1.5 text-gray-400">Totale</td>
                  {STATES.map((s) => (
                    <td key={s.key} className="px-2 py-1.5 text-right text-gray-200 font-mono">{totals[s.key] || 0}</td>
                  ))}
                  <td className="px-2 py-1.5 text-right text-gray-200 font-mono">
                    {Object.values(totals).reduce((sum, v) => sum + (v || 0), 0)}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {/* MTTR sub-block */}
        {mttr?.by_severity && Object.keys(mttr.by_severity).length > 0 && (
          <div className="mt-3 pt-3 border-t border-gray-800">
            <h4 className="text-xs uppercase text-gray-500 font-semibold mb-2">
              MTTR ultimi {mttr.period_days || 90} giorni
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {Object.entries(mttr.by_severity).map(([sev, data]) => (
                <div key={sev} className="bg-gray-800/50 border border-gray-700 rounded p-2">
                  <div className="text-[10px] text-gray-500">{sev}</div>
                  <div className="text-sm text-gray-100 font-mono">{data.mttr_days} gg</div>
                  <div className="text-[10px] text-gray-500">{data.count} chiusi</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
