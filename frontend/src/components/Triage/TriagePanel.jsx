'use client';

/**
 * Generic 1-row-per-CVE panel used by all four sections of Dashboard B.
 *
 * Caller passes an `accent` (colour and label of the section), an icon
 * hint, and the rows themselves. Each row is keyboard-activable and
 * fires `onSelectCve(cve_id)` on Enter/Space/click.
 *
 * The rendering is deliberately compact: every signal (severity, KEV,
 * PoC, Nuclei, EPSS, CVSS) is a small badge so the analyst can scan a
 * full panel in one second.
 */
import {
  SeverityBadge,
  KevBadge,
  PocBadge,
  NucleiBadge,
  PriorityScoreBadge,
} from '../UI/Badge';
import { fmtDate } from '../../lib/utils';

const ACCENTS = {
  red:    'border-red-700/60   bg-red-950/20',
  amber:  'border-amber-700/60 bg-amber-950/20',
  cyan:   'border-cyan-700/60  bg-cyan-950/20',
  violet: 'border-violet-700/60 bg-violet-950/20',
  gray:   'border-gray-800     bg-gray-900',
};

export default function TriagePanel({
  title,
  hint,
  rows,
  loading,
  emptyText = 'Nessun risultato.',
  accent = 'gray',
  onSelectCve,
  rightSlot,
  highlightField,
}) {
  return (
    <section
      aria-label={title}
      className={`rounded-xl border overflow-hidden ${ACCENTS[accent] || ACCENTS.gray}`}
    >
      <header className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800/60">
        <div>
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          {hint && <p className="text-xs text-gray-500 mt-0.5">{hint}</p>}
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <span aria-live="polite">
            {loading ? '…' : `${(rows || []).length} CVE`}
          </span>
          {rightSlot}
        </div>
      </header>

      {loading ? (
        <div className="py-6 text-center text-gray-500 text-sm">Caricamento…</div>
      ) : (rows || []).length === 0 ? (
        <div className="py-6 text-center text-gray-500 text-sm">{emptyText}</div>
      ) : (
        <ol className="divide-y divide-gray-800/50">
          {rows.map((c) => (
            <Row key={c.cve_id} c={c} onSelectCve={onSelectCve} highlightField={highlightField} />
          ))}
        </ol>
      )}
    </section>
  );
}

function Row({ c, onSelectCve, highlightField }) {
  const open = () => onSelectCve?.(c.cve_id);
  const cvss = c.cvss_v3_score ?? c.cvss_v2_score;
  const epssPct =
    c.epss_score != null ? `${(parseFloat(c.epss_score) * 100).toFixed(1)}%` : '—';

  // Highlight metric chosen by the panel: e.g. "days_in_kev" or
  // "exploitability_updated_at" — gives each section its own focal info.
  let highlight = null;
  if (highlightField === 'days_in_kev' && c.days_in_kev != null) {
    highlight = (
      <span className="text-[11px] text-amber-300 font-medium whitespace-nowrap">
        in KEV da {c.days_in_kev}gg
      </span>
    );
  } else if (highlightField === 'exploitability_updated_at' && c.exploitability_updated_at) {
    highlight = (
      <span className="text-[11px] text-violet-300 font-medium whitespace-nowrap">
        flag aggiornata {fmtDate(c.exploitability_updated_at)}
      </span>
    );
  } else if (highlightField === 'epss') {
    highlight = (
      <span className="text-[11px] text-cyan-300 font-medium whitespace-nowrap">
        EPSS {epssPct}
      </span>
    );
  }

  return (
    <li>
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
        className="flex items-center gap-2 px-4 py-2 hover:bg-gray-800/60 cursor-pointer focus:outline-none focus:bg-gray-800/80"
      >
        <PriorityScoreBadge score={c.priority_score} size="sm" />
        <span className="font-mono text-xs text-indigo-400 whitespace-nowrap">{c.cve_id}</span>
        <SeverityBadge severity={c.severity} />
        {c.in_cisa_kev && <KevBadge active />}
        <PocBadge has={c.has_public_poc} />
        <NucleiBadge has={c.has_nuclei_template} />
        <span className="text-xs text-gray-300 truncate flex-1 min-w-0" title={c.description}>
          {c.description || '—'}
        </span>
        <span className="text-[11px] text-gray-500 font-mono whitespace-nowrap shrink-0 hidden md:inline">
          CVSS {cvss != null ? Number(cvss).toFixed(1) : '—'}
        </span>
        {highlight}
      </div>
    </li>
  );
}
