'use client';

/**
 * Products with critical findings whose latest CVE was published over
 * 365 days ago — proxy for "no upstream patch in sight". The decision
 * for these is *replace*, not *patch*.
 */
import { fmtDate } from '../../lib/utils';

export default function EolFlagPanel({ items = [], loading, onSelectProduct }) {
  return (
    <section
      aria-label="Candidati EOL / legacy"
      className="bg-gray-900 border border-amber-900/60 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-amber-900/40 bg-amber-950/20">
        <h3 className="text-sm font-semibold text-amber-200">Candidati EOL / legacy</h3>
        <p className="text-xs text-amber-200/60">
          Critical findings con CVE non aggiornate da &gt; 365 giorni: pianificare upgrade, non patch
        </p>
      </header>
      {loading && items.length === 0 ? (
        <div className="py-4 text-center text-gray-500 text-sm">Caricamento…</div>
      ) : items.length === 0 ? (
        <div className="py-4 text-center text-gray-600 text-sm italic">
          Nessun candidato EOL: tutti i prodotti monitorati ricevono ancora aggiornamenti.
        </div>
      ) : (
        <ul className="divide-y divide-amber-900/30">
          {items.map((row) => (
            <li key={row.id}>
              <button
                type="button"
                onClick={() => onSelectProduct?.(row)}
                className="w-full text-left px-4 py-2 hover:bg-amber-950/30 focus:outline-none focus:bg-amber-950/40"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm text-amber-200 font-medium">{row.name}</span>
                  <span className="text-xs text-amber-300/70">{row.version}</span>
                  {row.vendor && (
                    <span className="text-[11px] text-gray-500">· {row.vendor}</span>
                  )}
                  <span className="ml-auto text-[11px] text-red-300 font-mono">
                    {row.critical_count} crit
                  </span>
                </div>
                <div className="text-[11px] text-gray-500 mt-0.5">
                  Ultima CVE modificata: {fmtDate(row.last_cve_modified)}
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
