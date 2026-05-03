'use client';
import { fmtDate } from '../../lib/utils';

const SYNC_BADGE = {
  running: { label: '⟳ sync…', cls: 'text-indigo-300 border-indigo-700 animate-pulse' },
  pending: { label: '⏳ in coda', cls: 'text-yellow-300 border-yellow-700' },
  failed:  { label: '✕ errore', cls: 'text-red-300 border-red-700' },
  done:    null,
  never:   null,
};

export default function ProductsGrid({ products, selectedId, onSelect, onDelete, onSync, onAdd }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-300">Prodotti monitorati</h3>
        <button
          onClick={onAdd}
          className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-lg transition"
        >
          + Aggiungi
        </button>
      </div>

      {products.length === 0 && (
        <div className="text-center py-8 text-gray-500 text-sm space-y-3">
          <p>Nessun prodotto. Aggiungi un prodotto per iniziare.</p>
          <button
            onClick={onAdd}
            className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-lg transition"
          >
            + Aggiungi il primo prodotto
          </button>
        </div>
      )}

      <ul className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
        {products.map((p) => {
          const syncBadge = SYNC_BADGE[p.sync_status];
          const selected = p.id === selectedId;
          return (
            <li key={p.id}>
              <div
                className={`rounded-lg border p-3 transition ${
                  selected
                    ? 'border-indigo-600 bg-indigo-950/50'
                    : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  {/* Selection action — proper button so it joins the tab order */}
                  <button
                    type="button"
                    onClick={() => onSelect(selected ? null : p.id)}
                    aria-pressed={selected}
                    aria-label={
                      selected
                        ? `Rimuovi filtro su ${p.name} ${p.version}`
                        : `Filtra CVE per ${p.name} ${p.version}`
                    }
                    className="text-left min-w-0 flex-1 focus:outline-none"
                  >
                    <div className="font-medium text-sm text-white truncate">{p.name}</div>
                    <div className="text-xs text-gray-400">
                      {p.version}{p.vendor ? ` · ${p.vendor}` : ''}
                    </div>
                  </button>
                  <div className="flex items-center gap-1 shrink-0 flex-wrap justify-end">
                    {syncBadge && (
                      <span
                        className={`text-xs bg-gray-900 border px-1.5 py-0.5 rounded ${syncBadge.cls}`}
                        title={p.sync_error || syncBadge.label}
                      >
                        {syncBadge.label}
                      </span>
                    )}
                    {parseInt(p.critical_count) > 0 && (
                      <span
                        className="text-xs bg-red-900/50 text-red-300 border border-red-700 px-1.5 py-0.5 rounded"
                        title={`${p.critical_count} CVE critiche su questo prodotto`}
                      >
                        {p.critical_count} crit
                      </span>
                    )}
                    <span
                      className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded"
                      title="CVE totali matchate al prodotto"
                    >
                      {p.cve_count} CVE
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between mt-2 gap-2">
                  <span className="text-xs text-gray-500 truncate">
                    {p.sync_status === 'running'
                      ? `Sync in corso… ${p.sync_cves_linked ?? 0} CVE`
                      : p.last_synced_at
                        ? `Sync: ${fmtDate(p.last_synced_at)}`
                        : 'Non ancora sincronizzato'}
                  </span>
                  <div className="flex gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={() => onSync(p.id)}
                      aria-label={`Re-sync ${p.name} ${p.version}`}
                      title="Re-sync"
                      className="text-xs text-indigo-400 hover:text-indigo-300 px-1.5 py-0.5 rounded border border-transparent hover:border-indigo-700 transition"
                    >↻ Sync</button>
                    <button
                      type="button"
                      onClick={() => onDelete(p.id)}
                      aria-label={`Elimina ${p.name} ${p.version}`}
                      title="Elimina (richiede conferma)"
                      className="text-xs text-red-400 hover:text-red-300 px-1.5 py-0.5 rounded border border-transparent hover:border-red-700 transition"
                    >✕ Elimina</button>
                  </div>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
