'use client';
import { useState } from 'react';
import { fmtDate, fmtScore, severityBg } from '../../lib/utils';

export default function ExportButtons({ filters, stats, products, selectedProductId }) {
  const [loadingPdf, setLoadingPdf] = useState(false);

  // CSV — call backend export endpoint directly
  function handleCsvExport() {
    const params = new URLSearchParams();
    if (filters.product_id || selectedProductId) params.set('product_id', filters.product_id || selectedProductId);
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.kev) params.set('kev', filters.kev);
    if (filters.min_epss) params.set('min_epss', filters.min_epss);
    if (filters.min_priority) params.set('min_priority', filters.min_priority);
    if (filters.keyword) params.set('keyword', filters.keyword);
    if (filters.year) params.set('year', filters.year);
    window.open(`/api/cves/export?${params.toString()}`, '_blank');
  }

  // PDF — client-side via jsPDF
  async function handlePdfExport() {
    setLoadingPdf(true);
    try {
      const { default: jsPDF } = await import('jspdf');
      const { default: autoTable } = await import('jspdf-autotable');

      // Fetch all CVEs for PDF (up to 500 rows)
      const params = new URLSearchParams({ limit: 500, sort: 'priority_score', order: 'desc' });
      if (filters.product_id || selectedProductId) params.set('product_id', filters.product_id || selectedProductId);
      if (filters.severity) params.set('severity', filters.severity);
      if (filters.kev) params.set('kev', filters.kev);
      if (filters.min_epss) params.set('min_epss', filters.min_epss);
      if (filters.min_priority) params.set('min_priority', filters.min_priority);
      if (filters.keyword) params.set('keyword', filters.keyword);
      if (filters.year) params.set('year', filters.year);

      const resp = await fetch(`/api/cves?${params.toString()}`);
      const { data: cves, total } = await resp.json();

      const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
      const now = new Date();
      const dateStr = now.toLocaleDateString('it-IT', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });

      const selectedProduct = products?.find(p => p.id === (filters.product_id || selectedProductId));

      // ── Header ──
      doc.setFillColor(17, 24, 39); // gray-900
      doc.rect(0, 0, 297, 30, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(16);
      doc.setFont('helvetica', 'bold');
      doc.text('CVE Management — Report', 14, 12);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(156, 163, 175);
      doc.text(`Generato il ${dateStr}`, 14, 19);
      if (selectedProduct) {
        doc.text(`Prodotto: ${selectedProduct.name} ${selectedProduct.version}`, 14, 25);
      }
      doc.text(`Totale CVE: ${total}${total > 500 ? ' (PDF limitato ai primi 500)' : ''}`, 200, 12);

      // ── Stats summary ──
      let y = 38;
      if (stats) {
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(55, 65, 81);
        doc.text('Sommario', 14, y);
        y += 5;

        const severity = Object.fromEntries((stats.severity || []).map(s => [s.severity, s.count]));
        const summaryItems = [
          ['CVE Totali', total],
          ['Critical', severity['CRITICAL'] || 0],
          ['High', severity['HIGH'] || 0],
          ['Medium', severity['MEDIUM'] || 0],
          ['CISA KEV', stats.kev_count || 0],
          ['Priority ≥80', stats.priority_distribution?.critical_priority || 0],
        ];

        let x = 14;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        for (const [label, value] of summaryItems) {
          doc.setFillColor(243, 244, 246);
          doc.roundedRect(x, y, 40, 14, 2, 2, 'F');
          doc.setTextColor(99, 102, 241);
          doc.setFontSize(13);
          doc.setFont('helvetica', 'bold');
          doc.text(String(value), x + 20, y + 7, { align: 'center' });
          doc.setTextColor(107, 114, 128);
          doc.setFontSize(7);
          doc.setFont('helvetica', 'normal');
          doc.text(label, x + 20, y + 12, { align: 'center' });
          x += 44;
        }
        y += 22;
      }

      // ── CVE Table ──
      const severityColors = {
        CRITICAL: [239, 68, 68],
        HIGH: [249, 115, 22],
        MEDIUM: [234, 179, 8],
        LOW: [59, 130, 246],
      };

      autoTable(doc, {
        startY: y,
        head: [['CVE ID', 'Severità', 'CVSS', 'EPSS', 'Priority', 'CISA KEV', 'Pubblicato', 'Descrizione']],
        body: cves.map(c => [
          c.cve_id,
          c.severity || '—',
          c.cvss_v3_score != null ? Number(c.cvss_v3_score).toFixed(1) : '—',
          c.epss_score != null ? `${(parseFloat(c.epss_score) * 100).toFixed(2)}%` : '—',
          `${c.priority_score || 0}/100`,
          c.in_cisa_kev ? '✓ KEV' : '',
          c.published_at ? new Date(c.published_at).toLocaleDateString('it-IT') : '—',
          (c.description || '').substring(0, 120) + (c.description?.length > 120 ? '…' : ''),
        ]),
        styles: { fontSize: 7, cellPadding: 2, overflow: 'linebreak' },
        headStyles: { fillColor: [31, 41, 55], textColor: [229, 231, 235], fontStyle: 'bold', fontSize: 7 },
        columnStyles: {
          0: { cellWidth: 28, fontStyle: 'bold', textColor: [99, 102, 241] },
          1: { cellWidth: 18 },
          2: { cellWidth: 12, halign: 'center' },
          3: { cellWidth: 14, halign: 'center' },
          4: { cellWidth: 16, halign: 'center' },
          5: { cellWidth: 16, halign: 'center', textColor: [168, 85, 247] },
          6: { cellWidth: 20 },
          7: { cellWidth: 'auto' },
        },
        didParseCell: (data) => {
          if (data.column.index === 1 && data.section === 'body') {
            const sev = data.cell.raw;
            const color = severityColors[sev];
            if (color) data.cell.styles.textColor = color;
          }
          if (data.column.index === 4 && data.section === 'body') {
            const score = parseInt(data.cell.raw);
            if (score >= 80) data.cell.styles.textColor = [239, 68, 68];
            else if (score >= 60) data.cell.styles.textColor = [249, 115, 22];
            else if (score >= 40) data.cell.styles.textColor = [234, 179, 8];
          }
        },
        alternateRowStyles: { fillColor: [249, 250, 251] },
        margin: { left: 14, right: 14 },
      });

      // Footer
      const pageCount = doc.getNumberOfPages();
      for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(7);
        doc.setTextColor(156, 163, 175);
        doc.text(`CVE Management Report — Pagina ${i} di ${pageCount}`, 148.5, 205, { align: 'center' });
      }

      doc.save(`cve-report-${now.toISOString().split('T')[0]}.pdf`);
    } catch (err) {
      console.error('PDF export error:', err);
      alert('Errore durante la generazione del PDF: ' + err.message);
    } finally {
      setLoadingPdf(false);
    }
  }

  return (
    <div className="flex gap-2">
      <button
        onClick={handleCsvExport}
        className="flex items-center gap-1.5 text-xs bg-gray-800 hover:bg-gray-700 border border-gray-600 text-gray-300 px-3 py-1.5 rounded-lg transition"
        title="Esporta CSV con i filtri attivi"
      >
        <span>⬇</span> CSV
      </button>
      <button
        onClick={handlePdfExport}
        disabled={loadingPdf}
        className="flex items-center gap-1.5 text-xs bg-gray-800 hover:bg-gray-700 border border-gray-600 text-gray-300 px-3 py-1.5 rounded-lg transition disabled:opacity-50"
        title="Genera report PDF con i filtri attivi"
      >
        {loadingPdf ? <span className="animate-spin">⟳</span> : <span>📄</span>} PDF
      </button>
    </div>
  );
}
