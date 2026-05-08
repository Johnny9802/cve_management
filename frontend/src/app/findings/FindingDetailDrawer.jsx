'use client';

/**
 * Finding detail drawer used by /findings.
 *
 * Side-sheet pattern: dimmed backdrop, focus trap, Escape closes,
 * focus returns to the row that opened it. Reuses the existing
 * useEscape + useFocusTrap hooks for parity with CVEDetailModal.
 *
 * Body shows:
 *   - badges (priority, severity, KEV, SLA)
 *   - product / version / CVE id (link to live intel)
 *   - description excerpt
 *   - FSM picker (Cambia stato → button list)
 *   - history timeline from /api/findings/{pid}/{cve}/history
 */
import { useEffect, useRef, useState } from 'react';
import { useEscape, useFocusTrap } from '../../lib/useDialog';
import {
  SeverityBadge,
  KevBadge,
  PriorityScoreBadge,
  FindingStatusBadge,
  SlaBadge,
} from '../../components/UI/Badge';
import { fmtDate } from '../../lib/utils';
import { getFindingHistory, updateFinding } from '../../lib/api';

const NEXT_TRANSITIONS = {
  open:           ['in_review', 'planned', 'false_positive'],
  in_review:      ['planned', 'remediated', 'false_positive', 'open'],
  planned:        ['in_review', 'remediated', 'open'],
  remediated:     ['closed', 'open'],
  accepted_risk:  ['open', 'remediated'],
  false_positive: ['open'],
  closed:         ['open'],
};

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

export default function FindingDetailDrawer({ finding, onClose, onChanged }) {
  const containerRef = useRef(null);
  useEscape(onClose);
  useFocusTrap(containerRef);

  const [history, setHistory] = useState([]);
  const [loadingHist, setLoadingHist] = useState(true);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState('');

  useEffect(() => {
    let alive = true;
    setLoadingHist(true);
    getFindingHistory(finding.product_id, finding.cve_id)
      .then((rows) => alive && setHistory(rows))
      .catch((e) => alive && setErr(e?.response?.data?.detail || e?.message || 'Errore'))
      .finally(() => alive && setLoadingHist(false));
    return () => { alive = false; };
  }, [finding]);

  async function changeStatus(next) {
    setBusy(true);
    setErr('');
    try {
      await updateFinding(finding.product_id, finding.cve_id, {
        status: next,
        reason: reason || undefined,
      });
      onChanged?.();
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setBusy(false);
    }
  }

  const next = NEXT_TRANSITIONS[finding.status] || [];

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Dettaglio finding ${finding.cve_id}`}
      className="fixed inset-0 z-40 flex justify-end"
    >
      <button
        type="button"
        aria-label="Chiudi"
        onClick={onClose}
        className="absolute inset-0 bg-black/50 cursor-default"
      />
      <div
        ref={containerRef}
        className="relative bg-gray-900 border-l border-gray-800 w-full max-w-md h-full overflow-y-auto p-5 space-y-4"
      >
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-1 flex-wrap">
              <PriorityScoreBadge score={finding.priority_score} />
              <SeverityBadge severity={finding.severity} />
              {finding.is_kev && <KevBadge active />}
              <FindingStatusBadge status={finding.status} />
            </div>
            <h2 className="font-mono text-indigo-400 text-sm">{finding.cve_id}</h2>
            <p className="text-xs text-gray-400">
              {finding.product_name} <span className="text-gray-500">{finding.product_version}</span>
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 hover:text-white text-lg leading-none px-2"
            aria-label="Chiudi pannello"
          >
            ×
          </button>
        </div>

        {finding.description && (
          <p className="text-xs text-gray-400 leading-relaxed">{finding.description}</p>
        )}

        <dl className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <dt className="text-gray-500 text-[10px] uppercase">SLA</dt>
            <dd>
              <SlaBadge state={dueDateState(finding)} />
              {finding.due_date && (
                <span className="text-gray-400 ml-1">{fmtDate(finding.due_date)}</span>
              )}
            </dd>
          </div>
          <div>
            <dt className="text-gray-500 text-[10px] uppercase">Owner</dt>
            <dd className="text-gray-300">{finding.assigned_to || '—'}</dd>
          </div>
          <div>
            <dt className="text-gray-500 text-[10px] uppercase">Aggiornato</dt>
            <dd className="text-gray-400">{fmtDate(finding.updated_at)}</dd>
          </div>
          <div>
            <dt className="text-gray-500 text-[10px] uppercase">Creato</dt>
            <dd className="text-gray-400">{fmtDate(finding.created_at)}</dd>
          </div>
        </dl>

        {/* Status picker */}
        {next.length > 0 && (
          <fieldset className="border border-gray-800 rounded-lg p-3 space-y-2">
            <legend className="px-1 text-xs text-gray-400">Cambia stato</legend>
            <label className="block text-[11px] text-gray-500">
              Motivazione (opzionale, salvata in history)
              <input
                type="text"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                disabled={busy}
                placeholder="Es. patch applicata, mitigazione approvata"
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-xs text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </label>
            <div className="flex flex-wrap gap-1.5">
              {next.map((s) => (
                <button
                  key={s}
                  type="button"
                  disabled={busy}
                  onClick={() => changeStatus(s)}
                  className="text-xs px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  → {s.replace('_', ' ')}
                </button>
              ))}
            </div>
            {err && (
              <p role="alert" className="text-[11px] text-red-400 mt-1">{err}</p>
            )}
          </fieldset>
        )}

        {/* History timeline */}
        <div className="border border-gray-800 rounded-lg p-3 space-y-2">
          <h3 className="text-xs text-gray-400 font-semibold">Storico</h3>
          {loadingHist ? (
            <p className="text-[11px] text-gray-600">Caricamento…</p>
          ) : history.length === 0 ? (
            <p className="text-[11px] text-gray-600 italic">Nessuna transizione registrata.</p>
          ) : (
            <ol className="space-y-1.5">
              {history.map((h) => (
                <li key={h.id} className="text-[11px] text-gray-400 flex gap-2">
                  <span className="text-gray-600 shrink-0">{fmtDate(h.changed_at)}</span>
                  <span>
                    <span className="text-gray-500">{h.old_status || 'init'}</span>
                    {' → '}
                    <span className="text-white">{h.new_status}</span>
                    {h.changed_by && (
                      <span className="text-gray-600 ml-1">@{h.changed_by}</span>
                    )}
                    {h.reason && (
                      <p className="text-gray-500 ml-0 mt-0.5 italic">{h.reason}</p>
                    )}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </div>
  );
}
