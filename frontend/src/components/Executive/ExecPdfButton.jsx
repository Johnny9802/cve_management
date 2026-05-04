'use client';

/**
 * Client-side PDF export of the Executive dashboard.
 *
 * Server-side PDF was the original ambition (deterministic, audit-ready)
 * but ships in Sprint 4 once weasyprint/reportlab is added to the
 * backend image. For the v1 dashboard we generate the PDF in-browser
 * with jsPDF — the dependency is already in package.json (used by the
 * CVE export). Output is good enough for a board pack screenshot.
 */
import { useState } from 'react';

export default function ExecPdfButton({ exec, periodDays }) {
  const [busy, setBusy] = useState(false);

  async function handleClick() {
    if (!exec) return;
    setBusy(true);
    try {
      const { default: jsPDF } = await import('jspdf');
      const { default: autoTable } = await import('jspdf-autotable');

      const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
      const now = new Date();
      const dateStr = now.toLocaleDateString('it-IT');

      // Header
      doc.setFillColor(17, 24, 39);
      doc.rect(0, 0, 210, 28, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(16);
      doc.setFont('helvetica', 'bold');
      doc.text('Executive Risk Overview', 14, 12);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(10);
      doc.setTextColor(156, 163, 175);
      doc.text(`Generato ${dateStr} · periodo ${periodDays} giorni`, 14, 19);

      const latest = exec.latest || {};
      const deltas = exec.deltas || {};

      // KPI strip
      let y = 38;
      doc.setTextColor(31, 41, 55);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.text('KPI principali', 14, y);
      y += 5;

      const kpis = [
        ['Risk score',        latest.risk_score ?? '—',           deltas.risk_score],
        ['KEV con finding',   latest.kev_with_open_finding ?? '—', deltas.kev_with_open_finding],
        ['Finding aperti',    latest.findings_open ?? '—',         deltas.findings_open],
        ['SLA breached',      latest.findings_breached ?? '—',     deltas.findings_breached],
      ];

      let x = 14;
      doc.setFontSize(8);
      for (const [label, val, delta] of kpis) {
        doc.setFillColor(243, 244, 246);
        doc.roundedRect(x, y, 45, 18, 2, 2, 'F');
        doc.setTextColor(99, 102, 241);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.text(String(val), x + 22, y + 8, { align: 'center' });
        doc.setTextColor(107, 114, 128);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'normal');
        doc.text(label, x + 22, y + 14, { align: 'center' });
        if (delta != null) {
          doc.setTextColor(delta > 0 ? 220 : 22, delta > 0 ? 38 : 163, delta > 0 ? 38 : 74);
          doc.text(`${delta > 0 ? '+' : ''}${delta}`, x + 22, y + 17.5, { align: 'center' });
        }
        x += 47;
      }
      y += 24;

      // Aging buckets
      const aging = exec.aging_buckets || {};
      doc.setTextColor(31, 41, 55);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.text('Aging dei finding open', 14, y);
      y += 5;
      autoTable(doc, {
        startY: y,
        head: [['0-30 gg', '30-90 gg', '90+ gg', 'Totale']],
        body: [[
          aging.bucket_0_30 || 0,
          aging.bucket_30_90 || 0,
          aging.bucket_90_plus || 0,
          aging.open_total || 0,
        ]],
        theme: 'striped',
        styles: { fontSize: 9, cellPadding: 2 },
        headStyles: { fillColor: [31, 41, 55], textColor: [229, 231, 235] },
        margin: { left: 14, right: 14 },
      });
      y = doc.lastAutoTable.finalY + 8;

      // Velocity weekly
      const velocity = exec.velocity_weekly || [];
      if (velocity.length > 0) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(11);
        doc.text('Velocity remediation (ultime 12 settimane)', 14, y);
        y += 5;
        autoTable(doc, {
          startY: y,
          head: [['Settimana', 'Remediated']],
          body: velocity.map((v) => [v.week, v.remediated_count]),
          theme: 'striped',
          styles: { fontSize: 9, cellPadding: 2 },
          headStyles: { fillColor: [31, 41, 55], textColor: [229, 231, 235] },
          margin: { left: 14, right: 14 },
        });
        y = doc.lastAutoTable.finalY + 8;
      }

      // Top owners
      const owners = exec.top_owners || [];
      if (owners.length > 0) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(11);
        doc.text('Top owners (90 gg)', 14, y);
        y += 5;
        autoTable(doc, {
          startY: y,
          head: [['Owner', 'Remediated', 'Breached', 'Totale']],
          body: owners.map((o) => [
            o.owner,
            o.remediated || 0,
            o.breached || 0,
            o.total || 0,
          ]),
          theme: 'striped',
          styles: { fontSize: 9, cellPadding: 2 },
          headStyles: { fillColor: [31, 41, 55], textColor: [229, 231, 235] },
          margin: { left: 14, right: 14 },
        });
      }

      // Footer
      const pageCount = doc.getNumberOfPages();
      for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(7);
        doc.setTextColor(156, 163, 175);
        doc.text(
          `CVE Management · Executive Report · pagina ${i}/${pageCount}`,
          105,
          290,
          { align: 'center' }
        );
      }

      doc.save(`exec-report-${now.toISOString().slice(0, 10)}.pdf`);
    } catch (err) {
      // eslint-disable-next-line no-alert
      alert(`Errore generazione PDF: ${err.message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={busy || !exec}
      className="text-xs bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg transition focus:outline-none"
      title="Esporta una sintesi PDF della dashboard"
    >
      {busy ? '…' : '⬇ Esporta PDF'}
    </button>
  );
}
