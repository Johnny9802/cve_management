'use client';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function CVEFilters({ filters, onChange }) {
  function set(key, value) {
    onChange({ ...filters, [key]: value, page: 1 });
  }

  return (
    <div className="flex flex-wrap gap-2 items-center">
      <input
        value={filters.keyword || ''}
        onChange={(e) => set('keyword', e.target.value)}
        placeholder="Cerca CVE ID o descrizione…"
        className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500 w-64"
      />

      <select
        value={filters.severity || ''}
        onChange={(e) => set('severity', e.target.value)}
        className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500"
      >
        <option value="">Tutte le severità</option>
        {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>

      <select
        value={filters.year || ''}
        onChange={(e) => set('year', e.target.value)}
        className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500"
      >
        <option value="">Tutti gli anni</option>
        {Array.from({ length: 10 }, (_, i) => new Date().getFullYear() - i).map((y) => (
          <option key={y} value={y}>{y}</option>
        ))}
      </select>

      <button
        type="button"
        onClick={() => set('kev', filters.kev === 'true' ? '' : 'true')}
        aria-pressed={filters.kev === 'true'}
        title={filters.kev === 'true' ? 'Mostra tutti i CVE' : 'Mostra solo CVE in CISA KEV'}
        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
          filters.kev === 'true'
            ? 'bg-purple-900/50 border-purple-600 text-purple-300'
            : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
        }`}
      >
        ● CISA KEV
      </button>

      <select
        value={filters.min_priority || ''}
        onChange={(e) => set('min_priority', e.target.value)}
        className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500"
      >
        <option value="">Priorità score ≥</option>
        <option value="80">≥ 80 (Critical Priority)</option>
        <option value="60">≥ 60 (High Priority)</option>
        <option value="40">≥ 40 (Medium Priority)</option>
      </select>

      {hasActiveFilters(filters) && (
        <button
          type="button"
          onClick={() => onChange({ page: 1, limit: 50, sort: 'priority_score', order: 'desc' })}
          title="Rimuovi tutti i filtri attivi"
          className="text-xs text-gray-400 hover:text-white px-2 py-1.5 border border-gray-700 rounded-lg transition"
        >
          ✕ Reset filtri
        </button>
      )}
    </div>
  );
}

// Returns true if any filter is set to a non-default, user-meaningful value.
function hasActiveFilters(filters) {
  const ignored = new Set(['page', 'limit', 'sort', 'order']);
  return Object.entries(filters).some(([k, v]) => {
    if (ignored.has(k)) return false;
    return v !== '' && v != null;
  });
}
