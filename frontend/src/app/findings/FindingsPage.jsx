'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  SeverityBadge,
  KevBadge,
  PriorityScoreBadge,
  FindingStatusBadge,
  SlaBadge,
} from '../../components/UI/Badge';
import { fmtDate } from '../../lib/utils';
import { getOpenFindings } from '../../lib/api';
import FindingDetailDrawer from './FindingDetailDrawer';

const STATUS_TABS = [
  { key: '',                label: 'Tutti'         },
  { key: 'open',            label: 'Open'          },
  { key: 'in_review',       label: 'In review'     },
  { key: 'planned',         label: 'Planned'       },
  { key: 'accepted_risk',   label: 'Accepted risk' },
  { key: 'remediated',      label: 'Remediated'    },
  { key: 'closed',          label: 'Closed'        },
  { key: 'false_positive',  label: 'False positive'},
];

function dueDateState(f) {
  if (!f.due_date) return 'on_track';
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const due = new Date(f.due_date);
  if (['remediated', 'closed', 'false_positive'].includes(f.status)) return 'met';
  if (due < today) return 'breached';
  const days = Math.round((due - today) / 86400000);
  if (days <= 7) return 'at_risk';
  return 'on_track';
}

export default function FindingsPage() {
  // URL is the source of truth so reload + share-link both work.
  const initialFromUrl = () => {
    if (typeof window === 'undefined') return { status: 'open', page: 1 };
    const params = new URLSearchParams(window.location.search);
    return {
      status: params.get('status') ?? 'open',
      page: Math.max(1, Number(params.get('page')) || 1),
    };
  };

  const [{ status, page }, setQuery] = useState(initialFromUrl);
  const [data, setData] = useState({ data: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);

  // Reflect state in the URL without hard navigation.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (page > 1) params.set('page', String(page));
    const qs = params.toString();
    const target = qs ? `?${qs}` : window.location.pathname;
    window.history.replaceState(null, '', target);
  }, [status, page]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = { page, limit: 50 };
      if (status) params.status = status;
      const payload = await getOpenFindings(params);
      setData({ data: payload.data || [], total: payload.total || 0 });
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Errore');
    } finally {
      setLoading(false);
    }
  }, [page, status]);

  useEffect(() => { load(); }, [load]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil((data.total || 0) / 50)),
    [data.total],
  );

  return (
    <div className="space-y-4">
      {/* Tab strip */}
      <div
        role="tablist"
        aria-label="Filtra per stato"
        className="flex flex-wrap gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1"
      >
        {STATUS_TABS.map((t) => {
          const active = status === t.key;
          return (
            <button
              key={t.key || 'all'}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setQuery({ status: t.key, page: 1 })}
              className={`text-xs px-3 py-1.5 rounded-lg transition ${
                active
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              }`}
            >
              {t.label}
            </button>
          );
        })}
        <span className="ml-auto text-[11px] text-gray-500 self-center pr-2" aria-live="polite">
          {data.total} finding
        </span>
      </div>

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-gray-950/50 text-gray-400 uppercase tracking-wide text-[10px]">
            <tr>
              <th className="px-3 py-2 text-left">Prio</th>
              <th className="px-3 py-2 text-left">Severity</th>
              <th className="px-3 py-2 text-left">CVE</th>
              <th className="px-3 py-2 text-left">Prodotto</th>
              <th className="px-3 py-2 text-left">Stato</th>
              <th className="px-3 py-2 text-left">SLA</th>
              <th className="px-3 py-2 text-left">Owner</th>
              <th className="px-3 py-2 text-left">Aggiornato</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading && data.data.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-600">Caricamento…</td></tr>
            )}
            {!loading && data.data.length === 0 && !error && (
              <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-600 italic">
                Nessun finding per questo filtro.
              </td></tr>
            )}
            {error && (
              <tr><td colSpan={8} className="px-3 py-4 text-center text-red-400">{error}</td></tr>
            )}
            {data.data.map((f) => (
              <tr
                key={f.id}
                tabIndex={0}
                role="button"
                aria-label={`Apri dettaglio finding ${f.cve_id} su ${f.product_name}`}
                onClick={() => setSelected(f)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelected(f);
                  }
                }}
                className="hover:bg-gray-800/60 cursor-pointer focus:outline-none focus:bg-gray-800"
              >
                <td className="px-3 py-2"><PriorityScoreBadge score={f.priority_score} size="sm" /></td>
                <td className="px-3 py-2">
                  <span className="inline-flex items-center gap-1">
                    <SeverityBadge severity={f.severity} />
                    {f.is_kev && <KevBadge active />}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-indigo-400">{f.cve_id}</td>
                <td className="px-3 py-2 text-gray-300 truncate max-w-[18ch]">
                  <span title={`${f.product_name} ${f.product_version}`}>
                    {f.product_name} <span className="text-gray-500">{f.product_version}</span>
                  </span>
                </td>
                <td className="px-3 py-2"><FindingStatusBadge status={f.status} /></td>
                <td className="px-3 py-2">
                  <SlaBadge state={dueDateState(f)} />
                  {f.due_date && (
                    <span className="text-[10px] text-gray-500 ml-1">{fmtDate(f.due_date)}</span>
                  )}
                </td>
                <td className="px-3 py-2 text-gray-400 truncate max-w-[14ch]" title={f.assigned_to || ''}>
                  {f.assigned_to || <span className="text-gray-700">—</span>}
                </td>
                <td className="px-3 py-2 text-gray-500">{fmtDate(f.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        {data.total > 50 && (
          <div className="flex items-center justify-between border-t border-gray-800 px-3 py-2 text-[11px] text-gray-500">
            <span>Pagina {page} di {totalPages}</span>
            <div className="flex gap-1">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setQuery((q) => ({ ...q, page: q.page - 1 }))}
                className="px-2 py-1 rounded border border-gray-700 hover:bg-gray-800 disabled:opacity-40 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                ← Prev
              </button>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setQuery((q) => ({ ...q, page: q.page + 1 }))}
                className="px-2 py-1 rounded border border-gray-700 hover:bg-gray-800 disabled:opacity-40 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>

      {selected && (
        <FindingDetailDrawer
          finding={selected}
          onClose={() => setSelected(null)}
          onChanged={() => { setSelected(null); load(); }}
        />
      )}
    </div>
  );
}
