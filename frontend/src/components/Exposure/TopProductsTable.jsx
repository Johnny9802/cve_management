'use client';

/**
 * Generic ranked-products table. Used twice on Dashboard C — once for
 * "by KEV", once for "by Critical". Click → drilldown placeholder
 * (Sprint Dashboards 4 may wire it to a product detail page).
 */
export default function TopProductsTable({ title, hint, rows = [], loading, emptyText, onSelectProduct }) {
  return (
    <section
      aria-label={title}
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        {hint && <p className="text-xs text-gray-500">{hint}</p>}
      </header>
      {loading && rows.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm">Caricamento…</div>
      ) : rows.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm italic">{emptyText || 'Nessun dato.'}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500">
              <th className="text-left px-3 py-1.5 font-medium">Prodotto</th>
              <th className="text-right px-3 py-1.5 font-medium">Crit</th>
              <th className="text-right px-3 py-1.5 font-medium">KEV</th>
              <th className="text-right px-3 py-1.5 font-medium">Tot</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-t border-gray-800">
                <td className="px-3 py-1.5">
                  <button
                    type="button"
                    onClick={() => onSelectProduct?.(row)}
                    className="text-left hover:text-indigo-300 focus:outline-none focus:underline"
                  >
                    <div className="font-medium text-gray-100 truncate max-w-[200px]">
                      {row.name}
                    </div>
                    <div className="text-[10px] text-gray-500 truncate max-w-[200px]">
                      {row.version}{row.vendor ? ` · ${row.vendor}` : ''}
                    </div>
                  </button>
                </td>
                <td className="px-3 py-1.5 text-right font-mono text-red-300">
                  {row.critical_count || 0}
                </td>
                <td className="px-3 py-1.5 text-right font-mono text-purple-300">
                  {row.kev_count || 0}
                </td>
                <td className="px-3 py-1.5 text-right font-mono text-gray-200">
                  {row.finding_count}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
