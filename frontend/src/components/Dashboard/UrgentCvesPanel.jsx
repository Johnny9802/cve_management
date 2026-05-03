'use client';

/**
 * "Top urgenze oggi" — first-class action panel on the dashboard.
 *
 * Renders the top N CVEs already provided by the backend (sorted by
 * priority_score desc), one row each, with the signals an analyst
 * actually triages on: priority badge + severity + CVSS + EPSS + KEV.
 *
 * Each row opens the CVE detail modal (shared with the main table).
 * The "Filtra: priority ≥ 80" button applies the same filter the
 * "Priorità Critica" KPI uses, so the user can dive into the full list
 * with one click.
 */
import { useMemo } from 'react';
import { fmtDate } from '../../lib/utils';
import {
  SeverityBadge,
  KevBadge,
  PriorityScoreBadge,
} from '../UI/Badge';

export default function UrgentCvesPanel({ cves = [], loading, onSelectCve, onFilterCriticalPriority }) {
  // Top 8 priority ≥ 60 from the current page; if all on this page are
  // low-priority we still show them so the panel never shows "—".
  const items = useMemo(() => {
    const sorted = [...(cves || [])].sort(
      (a, b) => (b.priority_score || 0) - (a.priority_score || 0)
    );
    return sorted.slice(0, 8);
  }, [cves]);

  return (
    <section
      aria-label="Top urgenze oggi"
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <div>
          <h3 className="text-sm font-semibold text-white">Top urgenze oggi</h3>
          <p className="text-xs text-gray-500">CVE con priority score più alto fra i risultati attuali</p>
        </div>
        <button
          type="button"
          onClick={onFilterCriticalPriority}
          className="text-xs bg-rose-900/40 hover:bg-rose-900/60 text-rose-200 border border-rose-800 px-3 py-1.5 rounded-lg transition focus:outline-none"
        >
          Filtra priority ≥ 80 →
        </button>
      </header>

      {loading ? (
        <div className="py-10 text-center text-gray-500 text-sm">Caricamento…</div>
      ) : items.length === 0 ? (
        <div className="py-10 text-center text-gray-500 text-sm">
          Nessuna CVE in questa lista. Aggiungi un prodotto o disattiva i filtri.
        </div>
      ) : (
        <ol className="divide-y divide-gray-800/70">
          {items.map((c) => {
            const open = () => onSelectCve?.(c.cve_id);
            const cvss = c.cvss_v3_score ?? c.cvss_v2_score;
            const epssPct =
              c.epss_score != null ? `${(parseFloat(c.epss_score) * 100).toFixed(1)}%` : '—';
            return (
              <li key={c.cve_id}>
                <div
                  role="button"
                  tabIndex={0}
                  onClick={open}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      open();
                    }
                  }}
                  aria-label={`Apri dettaglio ${c.cve_id}`}
                  className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-800/60 cursor-pointer focus:outline-none focus:bg-gray-800/80"
                >
                  <PriorityScoreBadge score={c.priority_score} size="md" />
                  <span className="font-mono text-xs text-indigo-400 whitespace-nowrap">{c.cve_id}</span>
                  <SeverityBadge severity={c.severity} />
                  {c.in_cisa_kev && <KevBadge active />}
                  <span className="text-xs text-gray-300 truncate flex-1" title={c.description}>
                    {c.description || '—'}
                  </span>
                  <span className="text-[11px] text-gray-500 font-mono whitespace-nowrap shrink-0">
                    CVSS {cvss != null ? Number(cvss).toFixed(1) : '—'} · EPSS {epssPct}
                  </span>
                  <span className="text-[11px] text-gray-600 whitespace-nowrap shrink-0 hidden md:inline">
                    {fmtDate(c.published_at)}
                  </span>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
