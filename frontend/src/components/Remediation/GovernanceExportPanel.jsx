'use client';

/**
 * Quick CSV exports for Dashboard D. Server-side PDF generation is
 * deferred to Sprint Dashboards 3 (requires reportlab/weasyprint on
 * the backend image).
 *
 * For now we expose:
 *  - SLA breached CSV: list of findings with sla_state=breached
 *  - Audit log CSV: recent audit entries
 *
 * The buttons fire client-side fetches and trigger a download via a
 * Blob URL — keeps the dependency surface tiny.
 */
import { useState } from 'react';
import { getSlaList, getAuditLog } from '../../lib/api';

function downloadCsv(filename, header, rows) {
  const lines = [header.join(',')];
  for (const row of rows) {
    lines.push(
      row
        .map((v) => {
          if (v == null) return '';
          const s = String(v).replace(/"/g, '""');
          return /[,\n"]/.test(s) ? `"${s}"` : s;
        })
        .join(',')
    );
  }
  const blob = new Blob(['﻿' + lines.join('\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function GovernanceExportPanel() {
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState('');

  async function exportSla() {
    setError('');
    setBusy('sla');
    try {
      const data = await getSlaList({ state: 'breached', limit: 500 });
      const rows = (data.data || []).map((f) => [
        f.cve_id,
        f.product_name,
        f.version,
        f.severity,
        f.is_kev ? 'YES' : 'NO',
        f.priority_score ?? '',
        f.status,
        f.due_date ?? '',
        f.days_overdue ?? 0,
        f.assigned_to ?? '',
      ]);
      downloadCsv(
        `sla-breached-${new Date().toISOString().slice(0, 10)}.csv`,
        ['CVE ID', 'Product', 'Version', 'Severity', 'KEV', 'Priority', 'Status', 'Due date', 'Days overdue', 'Owner'],
        rows
      );
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Errore export SLA');
    } finally {
      setBusy(null);
    }
  }

  async function exportAudit() {
    setError('');
    setBusy('audit');
    try {
      const data = await getAuditLog({ limit: 500 });
      const rows = (data.data || []).map((e) => [
        e.ts,
        e.action,
        e.actor_email || e.actor || 'system',
        e.actor_role || '',
        e.target_type || '',
        e.target_id || '',
        e.ip_address || '',
        e.diff ? JSON.stringify(e.diff) : '',
      ]);
      downloadCsv(
        `audit-log-${new Date().toISOString().slice(0, 10)}.csv`,
        ['Timestamp', 'Action', 'Actor', 'Role', 'Target type', 'Target id', 'IP', 'Diff (JSON)'],
        rows
      );
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Errore export audit');
    } finally {
      setBusy(null);
    }
  }

  return (
    <section
      aria-label="Export governance"
      className="bg-gray-900 border border-gray-800 rounded-xl p-3 flex flex-wrap items-center gap-2"
    >
      <span className="text-sm font-semibold text-white">Export governance</span>
      <button
        type="button"
        onClick={exportSla}
        disabled={busy != null}
        className="text-xs bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-100 border border-gray-700 px-3 py-1.5 rounded-lg transition focus:outline-none"
      >
        {busy === 'sla' ? '…' : '⬇ SLA breached (CSV)'}
      </button>
      <button
        type="button"
        onClick={exportAudit}
        disabled={busy != null}
        className="text-xs bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-100 border border-gray-700 px-3 py-1.5 rounded-lg transition focus:outline-none"
      >
        {busy === 'audit' ? '…' : '⬇ Audit log (CSV)'}
      </button>
      <span
        className="text-[11px] text-gray-600 ml-auto"
        title="PDF server-side disponibile in Sprint Dashboards 3"
      >
        PDF: Sprint 3
      </span>
      {error && (
        <p className="text-xs text-red-400 w-full" role="alert">{error}</p>
      )}
    </section>
  );
}
