'use client';

/**
 * Audit log report page (Sprint 2 — S2.3).
 *
 * Read-only view over /api/audit-log with filters by action prefix
 * and actor email. Useful for governance: "show me everything
 * @sec-team did this week" or "list every system.config_update".
 */
import { useCallback, useEffect, useState } from 'react';
import AppShell from '../../../components/Shell/AppShell';
import { getAuditLog } from '../../../lib/api';
import { fmtDate } from '../../../lib/utils';

export const dynamic = 'force-dynamic';

const ACTION_PREFIXES = [
  { key: '',                   label: 'Tutte'         },
  { key: 'auth.',              label: 'auth.*'        },
  { key: 'finding.',           label: 'finding.*'     },
  { key: 'product.',           label: 'product.*'     },
  { key: 'webhook.',           label: 'webhook.*'     },
  { key: 'risk_acceptance.',   label: 'risk_acceptance.*' },
  { key: 'system.',            label: 'system.*'      },
];

export default function Page() {
  const [actorEmail, setActorEmail] = useState('');
  const [actionPrefix, setActionPrefix] = useState('');
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = { limit: 100 };
      if (actorEmail) params.actor_email = actorEmail;
      if (actionPrefix) params.action_prefix = actionPrefix;
      const payload = await getAuditLog(params);
      setRows(payload?.data || []);
      setTotal(payload?.total ?? payload?.data?.length ?? 0);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setLoading(false);
    }
  }, [actorEmail, actionPrefix]);

  useEffect(() => { load(); }, [load]);

  return (
    <AppShell title="Audit log" subtitle="Storico mutazioni · login · governance" onRefresh={load}>
      {error && (
        <div role="alert" className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="flex flex-wrap items-end gap-2 bg-gray-900 border border-gray-800 rounded-xl p-3">
        <div>
          <label htmlFor="audit-actor" className="block text-[11px] text-gray-400 mb-1">
            Filtro actor email
          </label>
          <input
            id="audit-actor"
            type="email"
            placeholder="es. analyst@example.com"
            value={actorEmail}
            onChange={(e) => setActorEmail(e.target.value)}
            className="bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-xs text-white w-64 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <fieldset className="flex flex-col">
          <legend className="text-[11px] text-gray-400 mb-1 px-0">Filtro action</legend>
          <div role="radiogroup" aria-label="Filtro action" className="flex flex-wrap gap-1">
            {ACTION_PREFIXES.map((p) => (
              <button
                key={p.key || 'all'}
                type="button"
                role="radio"
                aria-checked={actionPrefix === p.key}
                onClick={() => setActionPrefix(p.key)}
                className={`text-[11px] px-2 py-1 rounded transition ${
                  actionPrefix === p.key
                    ? 'bg-indigo-600 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </fieldset>
        <span className="ml-auto text-[11px] text-gray-500" aria-live="polite">
          {total} eventi
        </span>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-gray-950/50 text-gray-400 uppercase tracking-wide text-[10px]">
            <tr>
              <th className="px-3 py-2 text-left">Quando</th>
              <th className="px-3 py-2 text-left">Action</th>
              <th className="px-3 py-2 text-left">Actor</th>
              <th className="px-3 py-2 text-left">Target</th>
              <th className="px-3 py-2 text-left">IP</th>
              <th className="px-3 py-2 text-left">Diff</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading && rows.length === 0 && (
              <tr><td colSpan={6} className="px-3 py-8 text-center text-gray-600">Caricamento…</td></tr>
            )}
            {!loading && rows.length === 0 && !error && (
              <tr><td colSpan={6} className="px-3 py-8 text-center text-gray-600 italic">
                Nessun evento per questi filtri.
              </td></tr>
            )}
            {rows.map((r) => (
              <tr key={r.id} className="hover:bg-gray-800/40 align-top">
                <td className="px-3 py-2 text-gray-500">{fmtDate(r.ts)}</td>
                <td className="px-3 py-2 font-mono text-indigo-300">{r.action}</td>
                <td className="px-3 py-2 text-gray-300 truncate max-w-[20ch]" title={r.actor_email || r.actor}>
                  {r.actor_email || r.actor}
                  {r.actor_role && (
                    <span className="ml-1 text-[10px] uppercase text-gray-500">{r.actor_role}</span>
                  )}
                </td>
                <td className="px-3 py-2 text-gray-400">
                  {r.target_type ? <code className="text-[10px]">{r.target_type}/{r.target_id ?? '—'}</code> : '—'}
                </td>
                <td className="px-3 py-2 text-gray-500 font-mono text-[10px]">{r.ip_address || '—'}</td>
                <td className="px-3 py-2 text-gray-400">
                  {r.diff && Object.keys(r.diff).length > 0 ? (
                    <details>
                      <summary className="cursor-pointer text-[11px] text-gray-500">apri</summary>
                      <pre className="text-[10px] text-gray-400 whitespace-pre-wrap mt-1">
                        {JSON.stringify(r.diff, null, 2)}
                      </pre>
                    </details>
                  ) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </AppShell>
  );
}
