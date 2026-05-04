'use client';

/**
 * Recent audit log timeline (Dashboard D — Sprint 2).
 *
 * Reads from /api/dashboard/remediation `audit_recent` (or
 * /api/audit-log directly when needed). Each entry shows actor,
 * action, target and a compact diff summary. Sensitive values (urls,
 * tokens) are already masked server-side by app/services/audit.py
 * `mask_sensitive`.
 */
import { useState } from 'react';

const ACTION_LABELS = {
  'finding.update':                    'Finding aggiornato',
  'finding.status_change':             'Cambio stato finding',
  'risk_acceptance.request':           'Richiesta accettazione rischio',
  'risk_acceptance.approve':           'Accettazione rischio approvata',
  'risk_acceptance.reject':            'Accettazione rischio rigettata',
  'risk_acceptance.expire':            'Accettazione rischio scaduta',
  'webhook.create':                    'Webhook creato',
  'webhook.update':                    'Webhook aggiornato',
  'webhook.delete':                    'Webhook eliminato',
  'product.create':                    'Prodotto aggiunto',
  'product.update':                    'Prodotto aggiornato',
  'product.delete':                    'Prodotto eliminato',
  'config.patch':                      'Configurazione aggiornata',
  'priority_recompute':                'Ricalcolo priority',
  'exploitability_changed':            'Exploitability cambiata',
};

function actionColor(action) {
  if (action.includes('approve') || action.includes('remediate')) return 'text-green-300';
  if (action.includes('reject') || action.includes('expire') || action.includes('breach')) return 'text-red-300';
  if (action.includes('status_change') || action.includes('update')) return 'text-indigo-300';
  if (action.includes('delete')) return 'text-amber-300';
  return 'text-gray-300';
}

export default function AuditTimeline({ events = [], loading, total }) {
  return (
    <section
      aria-label="Audit log recente"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">Audit log recente</h3>
          <p className="text-xs text-gray-500">
            Ultimi eventi (segreti / URL automaticamente mascherati lato server)
          </p>
        </div>
        <span className="text-xs text-gray-500">{total ?? events.length}</span>
      </header>

      {loading && events.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm">Caricamento…</div>
      ) : events.length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm italic">
          Nessun evento registrato.
        </div>
      ) : (
        <ol className="divide-y divide-gray-800/60 max-h-96 overflow-y-auto">
          {events.map((e) => (
            <li key={e.id}>
              <Entry e={e} />
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function Entry({ e }) {
  const [open, setOpen] = useState(false);
  const label = ACTION_LABELS[e.action] || e.action;
  const cls = actionColor(e.action);
  const target = [e.target_type, e.target_id].filter(Boolean).join(':');
  const ts = e.ts ? new Date(e.ts) : null;
  const tsLabel = ts
    ? `${ts.toLocaleDateString('it-IT')} ${ts.toLocaleTimeString('it-IT')}`
    : '';

  const hasDiff = e.diff && (e.diff.before || e.diff.after);

  return (
    <div className="px-4 py-2 hover:bg-gray-800/40">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-xs font-medium ${cls}`}>{label}</span>
        {target && (
          <span className="font-mono text-[11px] text-gray-400 truncate">{target}</span>
        )}
        <span className="text-[11px] text-gray-600 ml-auto whitespace-nowrap">
          {tsLabel}
        </span>
      </div>
      <div className="flex items-center gap-2 text-[11px] text-gray-500 mt-0.5">
        <span>{e.actor_email || e.actor || 'system'}</span>
        {e.actor_role && e.actor_role !== 'unknown' && (
          <span className="text-gray-600">· {e.actor_role}</span>
        )}
        {e.ip_address && (
          <span className="text-gray-600 font-mono">· {e.ip_address}</span>
        )}
        {hasDiff && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="ml-auto text-indigo-400 hover:text-indigo-300 focus:outline-none"
          >
            {open ? 'Nascondi diff' : 'Mostra diff'}
          </button>
        )}
      </div>
      {hasDiff && open && (
        <pre className="mt-1 bg-gray-950/70 border border-gray-800 rounded p-2 text-[10px] text-gray-300 overflow-x-auto">
          {JSON.stringify(e.diff, null, 2)}
        </pre>
      )}
    </div>
  );
}
