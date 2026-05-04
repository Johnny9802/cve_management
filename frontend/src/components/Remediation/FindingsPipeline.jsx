'use client';

/**
 * Kanban-style FSM column view of findings (Dashboard D — Sprint 2).
 *
 * The drag-and-drop variant from the design proposal is intentionally
 * deferred for v1. Status changes happen via a click-on-card menu
 * (FindingStatusPicker) — keyboard-friendly, mobile-friendly, no extra
 * dependency. Drag-and-drop can be added later via @dnd-kit when there
 * is a real volume of findings to justify it.
 *
 * Each column is scrollable; the count in the header is the total
 * (not the visible subset).
 */
import { useMemo, useState } from 'react';
import {
  SeverityBadge,
  KevBadge,
  PriorityScoreBadge,
  SlaBadge,
  FindingStatusBadge,
} from '../UI/Badge';
import { fmtDate } from '../../lib/utils';
import { updateFinding } from '../../lib/api';

const COLUMNS = [
  { key: 'open',           label: 'Open',           color: 'border-gray-700'    },
  { key: 'in_review',      label: 'In review',      color: 'border-blue-700'    },
  { key: 'planned',        label: 'Planned',        color: 'border-indigo-700'  },
  { key: 'accepted_risk',  label: 'Accepted risk',  color: 'border-yellow-700'  },
  { key: 'remediated',     label: 'Remediated',     color: 'border-green-700'   },
  { key: 'closed',         label: 'Closed',         color: 'border-green-600'   },
];

const NEXT_TRANSITIONS = {
  open:           ['in_review', 'planned', 'false_positive'],
  in_review:      ['planned', 'remediated', 'false_positive', 'open'],
  planned:        ['in_review', 'remediated', 'open'],
  remediated:     ['closed', 'open'],
  accepted_risk:  ['open', 'remediated'],
  false_positive: ['open'],
  closed:         ['open'],
};


function dueDateState(finding) {
  if (!finding.due_date) return 'on_track';
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const due = new Date(finding.due_date);
  if (['remediated', 'closed', 'false_positive'].includes(finding.status)) return 'met';
  if (due < today) return 'breached';
  const daysToDue = Math.round((due - today) / 86400000);
  if (daysToDue <= 7) return 'at_risk';
  return 'on_track';
}

function daysOverdue(finding) {
  if (!finding.due_date) return 0;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const due = new Date(finding.due_date);
  if (due >= today) return 0;
  return Math.round((today - due) / 86400000);
}

export default function FindingsPipeline({
  pipeline = {},
  findings = [],
  loading,
  onSelectCve,
  onChange,
}) {
  const grouped = useMemo(() => {
    const map = Object.fromEntries(COLUMNS.map((c) => [c.key, []]));
    for (const f of findings) {
      if (map[f.status]) map[f.status].push(f);
    }
    // sort by due_date ascending (most urgent first)
    for (const k of Object.keys(map)) {
      map[k].sort((a, b) => {
        if (a.due_date && b.due_date) return a.due_date.localeCompare(b.due_date);
        if (a.due_date) return -1;
        if (b.due_date) return 1;
        return 0;
      });
    }
    return map;
  }, [findings]);

  return (
    <section
      aria-label="Pipeline finding"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">Pipeline finding</h3>
          <p className="text-xs text-gray-500">Stato corrente di tutti i finding (FSM). Click sulla card per cambiare stato.</p>
        </div>
        <span className="text-xs text-gray-500">{pipeline.total ?? 0} totali</span>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-2 p-3">
        {COLUMNS.map((col) => {
          const items = grouped[col.key];
          const count = pipeline[`${col.key}_count`] ?? items.length;
          return (
            <div
              key={col.key}
              className={`rounded-lg border bg-gray-950/60 p-2 flex flex-col min-h-[180px] ${col.color}`}
            >
              <header className="flex items-center justify-between mb-2">
                <FindingStatusBadge status={col.key} />
                <span className="text-xs text-gray-400 font-mono">{count}</span>
              </header>
              {loading && items.length === 0 ? (
                <div className="text-xs text-gray-600 py-2 text-center">…</div>
              ) : items.length === 0 ? (
                <div className="text-[11px] text-gray-700 py-2 text-center italic">vuoto</div>
              ) : (
                <ul className="space-y-1.5 max-h-72 overflow-y-auto pr-0.5">
                  {items.slice(0, 30).map((f) => (
                    <li key={f.id}>
                      <FindingCard
                        finding={f}
                        onSelectCve={onSelectCve}
                        onChange={onChange}
                      />
                    </li>
                  ))}
                  {items.length > 30 && (
                    <li className="text-[10px] text-gray-700 text-center pt-1">
                      … e altri {items.length - 30}
                    </li>
                  )}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function FindingCard({ finding, onSelectCve, onChange }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const sla = dueDateState(finding);
  const overdue = daysOverdue(finding);

  async function changeStatus(next) {
    setBusy(true);
    setErr('');
    try {
      await updateFinding(finding.product_id, finding.cve_id, { status: next, actor: 'ui' });
      setMenuOpen(false);
      onChange?.();
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setBusy(false);
    }
  }

  const next = NEXT_TRANSITIONS[finding.status] || [];

  return (
    <div className="rounded border border-gray-800 bg-gray-900 p-2 text-[11px] space-y-1">
      <div className="flex items-center gap-1 flex-wrap">
        <PriorityScoreBadge score={finding.priority_score} size="sm" />
        <SeverityBadge severity={finding.severity} />
        {finding.is_kev && <KevBadge active />}
      </div>
      <button
        type="button"
        onClick={() => onSelectCve?.(finding.cve_id)}
        className="font-mono text-indigo-400 hover:text-indigo-300 text-[11px] truncate text-left w-full focus:outline-none"
        aria-label={`Apri dettaglio ${finding.cve_id}`}
      >
        {finding.cve_id}
      </button>
      <div className="text-[10px] text-gray-400 truncate" title={`${finding.product_name} ${finding.version}`}>
        {finding.product_name} {finding.version}
      </div>
      <div className="flex items-center gap-1 flex-wrap">
        <SlaBadge state={sla} daysOverdue={overdue || undefined} />
        {finding.due_date && (
          <span className="text-[10px] text-gray-500">{fmtDate(finding.due_date)}</span>
        )}
        {finding.assigned_to && (
          <span className="text-[10px] text-gray-500 truncate">@{finding.assigned_to}</span>
        )}
      </div>

      {next.length > 0 && (
        <div className="pt-1 border-t border-gray-800">
          {!menuOpen ? (
            <button
              type="button"
              onClick={() => setMenuOpen(true)}
              className="w-full text-[10px] text-indigo-400 hover:text-indigo-300 py-0.5 rounded focus:outline-none"
            >
              Cambia stato →
            </button>
          ) : (
            <div className="flex flex-wrap gap-1 pt-0.5">
              {next.map((s) => (
                <button
                  key={s}
                  type="button"
                  disabled={busy}
                  onClick={() => changeStatus(s)}
                  className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 disabled:opacity-50"
                >
                  {s.replace('_', ' ')}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setMenuOpen(false)}
                className="text-[10px] px-1.5 py-0.5 rounded text-gray-500 hover:text-white"
              >
                ✕
              </button>
            </div>
          )}
          {err && <p className="text-[10px] text-red-400 pt-0.5" role="alert">{err}</p>}
        </div>
      )}
    </div>
  );
}
