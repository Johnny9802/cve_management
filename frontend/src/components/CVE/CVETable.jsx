'use client';
import { fmtDate, fmtScore } from '../../lib/utils';
import {
  SeverityBadge,
  KevBadge,
  PriorityScoreBadge,
  SourceBadge,
  MatchBadge,
} from '../UI/Badge';

export default function CVETable({ data = [], total, page, pages, onPageChange, onRowClick, loading, onAddProduct }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <span className="text-xs text-gray-400">{total?.toLocaleString()} CVE trovati</span>
        {pages > 1 && (
          <div className="flex items-center gap-2 text-xs">
            <button
              disabled={page <= 1}
              onClick={() => onPageChange(page - 1)}
              aria-label="Pagina precedente"
              className="px-2 py-1 rounded bg-gray-800 text-gray-300 disabled:opacity-40 hover:bg-gray-700 transition"
            >‹</button>
            <span className="text-gray-400">{page} / {pages}</span>
            <button
              disabled={page >= pages}
              onClick={() => onPageChange(page + 1)}
              aria-label="Pagina successiva"
              className="px-2 py-1 rounded bg-gray-800 text-gray-300 disabled:opacity-40 hover:bg-gray-700 transition"
            >›</button>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16 text-gray-500 text-sm">Caricamento…</div>
      ) : data.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 gap-3">
          {total === 0 && !loading ? (
            <>
              <p className="text-gray-400 text-sm">Nessun CVE nel database locale.</p>
              <p className="text-gray-600 text-xs">Aggiungi un prodotto per avviare la sincronizzazione, oppure usa <strong className="text-gray-400">Cerca NVD Live</strong> per ricerche in tempo reale.</p>
              {onAddProduct && (
                <button onClick={onAddProduct} className="mt-1 text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg transition">
                  + Aggiungi prodotto
                </button>
              )}
            </>
          ) : (
            <p className="text-gray-500 text-sm">Nessun CVE trovato con i filtri selezionati.</p>
          )}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-800">
                <th scope="col" className="text-left px-4 py-2.5 font-medium">CVE ID</th>
                <th scope="col" className="text-left px-4 py-2.5 font-medium">Descrizione</th>
                <th scope="col" className="text-left px-4 py-2.5 font-medium">Severità</th>
                <th scope="col" className="text-right px-4 py-2.5 font-medium">CVSS</th>
                <th scope="col" className="text-right px-4 py-2.5 font-medium">EPSS</th>
                <th scope="col" className="text-right px-4 py-2.5 font-medium">Priority</th>
                <th scope="col" className="text-left px-4 py-2.5 font-medium">Pubblicato</th>
                <th scope="col" className="text-center px-4 py-2.5 font-medium">KEV</th>
                <th scope="col" className="text-center px-4 py-2.5 font-medium">Match</th>
                <th scope="col" className="text-center px-4 py-2.5 font-medium">Fonte</th>
              </tr>
            </thead>
            <tbody>
              {data.map((cve) => {
                const handleActivate = () => onRowClick(cve.cve_id);
                return (
                  <tr
                    key={cve.cve_id}
                    onClick={handleActivate}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleActivate();
                      }
                    }}
                    role="button"
                    tabIndex={0}
                    aria-label={`Apri dettaglio ${cve.cve_id}`}
                    className="border-b border-gray-800/60 hover:bg-gray-800/50 cursor-pointer transition focus:outline-none focus:bg-gray-800/70"
                  >
                    <td className="px-4 py-2.5 font-mono text-indigo-400 whitespace-nowrap">{cve.cve_id}</td>
                    <td className="px-4 py-2.5 text-gray-300 max-w-xs">
                      <div className="truncate" title={cve.description}>{cve.description || '—'}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={cve.severity} />
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-gray-300">{fmtScore(cve.cvss_v3_score)}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-gray-300">
                      {cve.epss_score != null ? `${(parseFloat(cve.epss_score) * 100).toFixed(2)}%` : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <div className="flex items-center gap-2 justify-end">
                        <PriorityScoreBadge score={cve.priority_score} size="sm" />
                        <PriorityBar score={cve.priority_score} />
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-gray-400 whitespace-nowrap">{fmtDate(cve.published_at)}</td>
                    <td className="px-4 py-2.5 text-center">
                      {cve.in_cisa_kev ? <KevBadge active /> : <span aria-hidden className="text-gray-700">—</span>}
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      <MatchBadge confidence={cve.match_confidence} />
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      <SourceBadge source={cve.source} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Visual-only inline progress bar (kept next to the numeric badge).
function PriorityBar({ score }) {
  const s = parseInt(score) || 0;
  let color = 'bg-blue-600';
  if (s >= 80) color = 'bg-red-600';
  else if (s >= 60) color = 'bg-orange-500';
  else if (s >= 40) color = 'bg-yellow-500';
  return (
    <div
      className="w-16 bg-gray-800 rounded-full h-1.5"
      aria-hidden
    >
      <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${s}%` }} />
    </div>
  );
}
