'use client';

/**
 * Shared Badge primitives.
 *
 * Replaces ad-hoc inline `bg-*` styles scattered across CVETable,
 * CVEDetailModal, LiveSearchPanel etc. so that the visual language is
 * coherent and accessible (real text, no emoji-only signals).
 *
 * All badges are non-interactive `<span>` by default. Pass `as="button"`
 * + `onClick` to make them interactive (filter chips). The interactive
 * variant gets cursor-pointer, hover halo, focus ring and aria-pressed.
 */
import React from 'react';

const SEVERITY_CLASSES = {
  CRITICAL: 'bg-red-900/40 text-red-300 border-red-700',
  HIGH:     'bg-orange-900/40 text-orange-300 border-orange-700',
  MEDIUM:   'bg-yellow-900/40 text-yellow-300 border-yellow-700',
  LOW:      'bg-blue-900/40 text-blue-300 border-blue-700',
  NONE:     'bg-gray-800 text-gray-400 border-gray-700',
};

const STATUS_CLASSES = {
  open:           'bg-gray-800 text-gray-200 border-gray-600',
  in_review:      'bg-blue-900/40 text-blue-300 border-blue-700',
  planned:        'bg-indigo-900/40 text-indigo-300 border-indigo-700',
  false_positive: 'bg-gray-900 text-gray-400 border-gray-700',
  accepted_risk:  'bg-yellow-900/40 text-yellow-300 border-yellow-700',
  remediated:     'bg-green-900/40 text-green-300 border-green-700',
  closed:         'bg-green-900/60 text-green-200 border-green-600',
};

const SLA_CLASSES = {
  met:       'bg-green-900/40 text-green-300 border-green-700',
  on_track:  'bg-gray-800 text-gray-300 border-gray-600',
  at_risk:   'bg-amber-900/40 text-amber-300 border-amber-700',
  breached:  'bg-red-900/40 text-red-300 border-red-700',
};

const SOURCE_META = {
  nvd_api:       { label: 'NVD',         cls: 'bg-blue-900/40 text-blue-300 border-blue-800',
                   tooltip: 'Cache locale — NVD API v2' },
  vulncheck_nvd: { label: 'VulnCheck',   cls: 'bg-indigo-900/40 text-indigo-300 border-indigo-800',
                   tooltip: 'Cache locale — VulnCheck NVD++' },
  circl:         { label: 'CIRCL',       cls: 'bg-teal-900/40 text-teal-300 border-teal-800',
                   tooltip: 'Recuperato da CIRCL Vulnerability-Lookup' },
};

// ───────────────────────────────────────────── base wrapper

function Pill({
  as = 'span',
  className = '',
  tooltip,
  ariaLabel,
  ariaPressed,
  onClick,
  type,
  children,
  ...rest
}) {
  const Tag = as;
  const interactive = as === 'button';
  const hasTooltip = !!tooltip;
  const cls = [
    'inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium whitespace-nowrap',
    interactive
      ? 'cursor-pointer hover:brightness-125 transition'
      : '',
    hasTooltip ? 'has-tooltip' : '',
    className,
  ].filter(Boolean).join(' ');
  return (
    <Tag
      className={cls}
      data-tooltip={tooltip}
      aria-label={ariaLabel || tooltip}
      aria-pressed={interactive && ariaPressed != null ? ariaPressed : undefined}
      onClick={onClick}
      type={interactive ? (type || 'button') : undefined}
      tabIndex={interactive ? 0 : undefined}
      {...rest}
    >
      {children}
    </Tag>
  );
}

// ───────────────────────────────────────────── exports

export function SeverityBadge({ severity, ...rest }) {
  const key = (severity || 'NONE').toUpperCase();
  return (
    <Pill className={SEVERITY_CLASSES[key] || SEVERITY_CLASSES.NONE} {...rest}>
      {severity || '—'}
    </Pill>
  );
}

export function KevBadge({ active = true, onClick, ...rest }) {
  if (!active) return null;
  return (
    <Pill
      className="bg-purple-900/40 text-purple-300 border-purple-700"
      tooltip="In CISA KEV — sfruttamento attivo confermato"
      as={onClick ? 'button' : 'span'}
      onClick={onClick}
      {...rest}
    >
      <span aria-hidden="true">●</span> KEV
    </Pill>
  );
}

export function EpssBadge({ score, percentile, ...rest }) {
  if (score == null) return null;
  const pct = (parseFloat(score) * 100).toFixed(2);
  const tooltip = percentile != null
    ? `EPSS ${pct}% — ${(parseFloat(percentile) * 100).toFixed(0)}° percentile`
    : `EPSS ${pct}%`;
  return (
    <Pill
      className="bg-cyan-900/40 text-cyan-300 border-cyan-800"
      tooltip={tooltip}
      {...rest}
    >
      EPSS {pct}%
    </Pill>
  );
}

export function PocBadge({ has, ...rest }) {
  if (has === true) {
    return (
      <Pill
        className="bg-emerald-900/40 text-emerald-300 border-emerald-700"
        tooltip="Public PoC disponibile"
        {...rest}
      >
        PoC
      </Pill>
    );
  }
  if (has === false) return null;
  // null/undefined → unknown (vulnx not queried)
  return (
    <Pill
      className="bg-gray-800 text-gray-500 border-gray-700"
      tooltip="PoC: ignoto — vulnx non interrogato"
      {...rest}
    >
      PoC ?
    </Pill>
  );
}

export function NucleiBadge({ has, ...rest }) {
  if (has === true) {
    return (
      <Pill
        className="bg-fuchsia-900/40 text-fuchsia-300 border-fuchsia-700"
        tooltip="Template Nuclei disponibile — exploit weaponizzato per scan di massa"
        {...rest}
      >
        Nuclei
      </Pill>
    );
  }
  if (has === false) return null;
  return null;
}

export function PriorityScoreBadge({ score, size = 'md', ...rest }) {
  const s = parseInt(score) || 0;
  let cls = 'bg-blue-900/40 text-blue-300 border-blue-700';
  let label = 'MONITOR';
  if (s >= 80) { cls = 'bg-red-900/50 text-red-300 border-red-700'; label = 'CRITICAL'; }
  else if (s >= 60) { cls = 'bg-orange-900/40 text-orange-300 border-orange-700'; label = 'HIGH'; }
  else if (s >= 40) { cls = 'bg-yellow-900/40 text-yellow-300 border-yellow-700'; label = 'MEDIUM'; }
  const tooltip = `Priority ${s}/100 — ${label}`;
  return (
    <Pill className={cls} tooltip={tooltip} ariaLabel={tooltip} {...rest}>
      <span className="font-mono">{s}</span>
      {size !== 'sm' && <span className="opacity-70">/100</span>}
    </Pill>
  );
}

export function FindingStatusBadge({ status, ...rest }) {
  const cls = STATUS_CLASSES[status] || 'bg-gray-800 text-gray-400 border-gray-700';
  return (
    <Pill className={cls} {...rest}>
      {(status || '—').replace(/_/g, ' ')}
    </Pill>
  );
}

export function SlaBadge({ state, daysOverdue, ...rest }) {
  if (!state) return null;
  const cls = SLA_CLASSES[state] || SLA_CLASSES.on_track;
  const tooltip = state === 'breached' && daysOverdue
    ? `SLA breached — ${daysOverdue} giorni di ritardo`
    : `SLA ${state.replace('_', ' ')}`;
  return (
    <Pill className={cls} tooltip={tooltip} {...rest}>
      SLA {state.replace('_', ' ')}
    </Pill>
  );
}

export function SourceBadge({ source, ...rest }) {
  if (!source) return null;
  const meta = SOURCE_META[source] || {
    label: source,
    cls: 'bg-gray-800 text-gray-400 border-gray-700',
    tooltip: source,
  };
  return (
    <Pill className={meta.cls} tooltip={meta.tooltip} {...rest}>
      {meta.label}
    </Pill>
  );
}

export function MatchBadge({ confidence, ...rest }) {
  if (!confidence) return null;
  const map = {
    certain: {
      label: 'Confirmed',
      cls: 'bg-green-900/40 text-green-300 border-green-700',
      tooltip: 'Version range confirmed by local CPE evaluation',
    },
    cpe_search: {
      label: 'NVD-matched',
      cls: 'bg-emerald-900/40 text-emerald-300 border-emerald-700',
      tooltip: 'Matched via NVD CPE search (version-range validated by NVD)',
    },
    uncertain: {
      label: 'Uncertain',
      cls: 'bg-yellow-900/40 text-yellow-300 border-yellow-700',
      tooltip: 'Uncertain match — review manually',
    },
  };
  const m = map[confidence] || {
    label: confidence,
    cls: 'bg-gray-800 text-gray-400 border-gray-700',
    tooltip: `Match: ${confidence}`,
  };
  return (
    <Pill className={m.cls} tooltip={m.tooltip} {...rest}>
      {m.label}
    </Pill>
  );
}

const Badges = {
  SeverityBadge,
  KevBadge,
  EpssBadge,
  PocBadge,
  NucleiBadge,
  PriorityScoreBadge,
  FindingStatusBadge,
  SlaBadge,
  SourceBadge,
  MatchBadge,
};

export default Badges;
