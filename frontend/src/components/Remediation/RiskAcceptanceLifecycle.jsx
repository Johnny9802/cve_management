'use client';

/**
 * Risk-acceptance counters + the two operational lists:
 *  - pending: requests waiting for an approver
 *  - expiring soon: approved acceptances about to expire
 *
 * Both lists are clickable rows that route to the underlying finding.
 */
import { fmtDate } from '../../lib/utils';
import { SeverityBadge } from '../UI/Badge';

const STATES = [
  { key: 'pending',       label: 'In attesa',     cls: 'bg-blue-900/30 text-blue-200 border-blue-700' },
  { key: 'approved',      label: 'Approvati',     cls: 'bg-green-900/30 text-green-200 border-green-700' },
  { key: 'expiring_soon', label: 'In scadenza',   cls: 'bg-amber-900/30 text-amber-200 border-amber-700' },
  { key: 'rejected',      label: 'Rigettati',     cls: 'bg-gray-800 text-gray-300 border-gray-700' },
  { key: 'expired',       label: 'Scaduti',       cls: 'bg-red-900/30 text-red-200 border-red-700' },
];

export default function RiskAcceptanceLifecycle({ summary, loading, onSelectFinding }) {
  const counters = summary?.counters || {};
  const window = summary?.expiring_window_days || 7;
  const pending = summary?.pending_recent || [];
  const expiring = summary?.expiring_soon || [];

  return (
    <section
      aria-label="Risk acceptance"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-white">Accettazioni rischio</h3>
        <p className="text-xs text-gray-500">Lifecycle: pending → approved/rejected → expired</p>
      </header>

      <div className="p-3 space-y-3">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          {STATES.map((s) => (
            <div
              key={s.key}
              className={`rounded border p-2 ${s.cls}`}
              title={s.key === 'expiring_soon' ? `Approvati in scadenza nei prossimi ${window} giorni` : s.label}
            >
              <div className="text-[10px] uppercase opacity-75">{s.label}</div>
              <div className="text-xl font-bold mt-0.5">{loading ? '…' : (counters[s.key] ?? 0)}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <SubList
            title="Da approvare"
            empty="Nessuna richiesta in attesa."
            rows={pending}
            metric={(r) => `richiesto ${fmtDate(r.created_at)}`}
            onSelectFinding={onSelectFinding}
          />
          <SubList
            title={`In scadenza (${window}gg)`}
            empty="Nessuna accettazione in scadenza."
            rows={expiring}
            metric={(r) => `tra ${r.days_remaining} gg`}
            onSelectFinding={onSelectFinding}
          />
        </div>
      </div>
    </section>
  );
}

function SubList({ title, empty, rows, metric, onSelectFinding }) {
  return (
    <div>
      <h4 className="text-xs uppercase text-gray-500 font-semibold mb-1.5">{title}</h4>
      {rows.length === 0 ? (
        <div className="text-xs text-gray-600 italic">{empty}</div>
      ) : (
        <ul className="space-y-1">
          {rows.map((r) => (
            <li key={r.id}>
              <button
                type="button"
                onClick={() =>
                  onSelectFinding?.({ product_id: r.product_id, cve_id: r.cve_id })
                }
                className="w-full text-left flex items-center gap-2 px-2 py-1 rounded hover:bg-gray-800 focus:outline-none"
              >
                <SeverityBadge severity={r.severity} />
                <span className="font-mono text-xs text-indigo-400 whitespace-nowrap">{r.cve_id}</span>
                <span className="text-xs text-gray-300 truncate flex-1">
                  {r.product_name} {r.version}
                </span>
                <span className="text-[11px] text-gray-500 whitespace-nowrap">{metric(r)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
