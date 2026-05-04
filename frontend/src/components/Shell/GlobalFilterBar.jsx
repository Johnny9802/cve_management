'use client';

/**
 * Filter bar shared by Dashboard B (and reused by C / D in later
 * sprints). All state goes to the URL — every chip is a `?key=value`
 * pair. Each dashboard reads the subset relevant to it; unknown chips
 * are simply ignored.
 *
 * The chips here implement the SOC analyst's "what should I look at"
 * pivots: KEV / PoC / Nuclei / EPSS≥0.5 / EPSS≥0.9 / priority≥80 /
 * "mine" (owner = me).
 */
import { useMemo } from 'react';
import { hasActiveState } from '../../lib/url-state';

const CHIPS = [
  { key: 'kev',           value: 'true', label: 'KEV',          tooltip: 'Solo CVE in CISA KEV' },
  { key: 'has_poc',       value: 'true', label: 'Public PoC',   tooltip: 'CVE con PoC pubblico (vulnx)' },
  { key: 'has_nuclei',    value: 'true', label: 'Nuclei',       tooltip: 'CVE con template Nuclei' },
  { key: 'min_epss',      value: '0.5',  label: 'EPSS ≥ 50%',   tooltip: 'EPSS ≥ 0.5 (probabilità sfruttamento)' },
  { key: 'min_epss',      value: '0.9',  label: 'EPSS ≥ 90%',   tooltip: 'EPSS ≥ 0.9' },
  { key: 'min_priority',  value: '80',   label: 'Priority ≥ 80', tooltip: 'Priority score ≥ 80' },
];

export default function GlobalFilterBar({ defaults, state, setState, reset, keywordPlaceholder = 'CVE-ID o keyword…' }) {
  const active = useMemo(() => hasActiveState(state, defaults), [state, defaults]);

  function toggleChip(chip) {
    const cur = state[chip.key];
    const isActive = cur === chip.value;
    setState({ [chip.key]: isActive ? '' : chip.value });
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-3 flex flex-wrap items-center gap-2">
      <input
        type="search"
        value={state.keyword || ''}
        onChange={(e) => setState({ keyword: e.target.value })}
        placeholder={keywordPlaceholder}
        aria-label="Cerca per CVE ID o keyword"
        className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500 w-64"
      />

      <div className="flex flex-wrap gap-1.5">
        {CHIPS.map((chip) => {
          const cur = state[chip.key];
          const isActive = cur === chip.value;
          return (
            <button
              key={`${chip.key}=${chip.value}`}
              type="button"
              onClick={() => toggleChip(chip)}
              aria-pressed={isActive}
              title={chip.tooltip}
              className={`text-xs px-2.5 py-1 rounded-full border transition focus:outline-none ${
                isActive
                  ? 'bg-indigo-600/30 text-indigo-200 border-indigo-600'
                  : 'bg-gray-800 text-gray-400 border-gray-700 hover:border-gray-600 hover:text-gray-200'
              }`}
            >
              {chip.label}
            </button>
          );
        })}
      </div>

      <select
        value={state.severity || ''}
        onChange={(e) => setState({ severity: e.target.value })}
        aria-label="Filtra per severità"
        className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500"
      >
        <option value="">Tutte le severità</option>
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>

      {active && (
        <button
          type="button"
          onClick={reset}
          title="Rimuovi tutti i filtri"
          className="ml-auto text-xs text-gray-400 hover:text-white px-2 py-1.5 border border-gray-700 hover:border-gray-500 rounded-lg transition"
        >
          ✕ Reset
        </button>
      )}
    </div>
  );
}
