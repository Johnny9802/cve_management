'use client';

/**
 * KPI strip with mixed interactive / static tiles.
 *
 * Critical, High, In CISA KEV and Priorità Critica tiles are clickable
 * and trigger an `onFilterChange` callback so they map directly to the
 * relevant CVE filter. The remaining tiles ("Prodotti monitorati",
 * "CVE totali") stay static — no faux affordance.
 */
export default function StatsBar({ stats, onFilter, activeFilters = {} }) {
  if (!stats) return null;

  const severity = Object.fromEntries(
    (stats.severity || []).map((s) => [s.severity, parseInt(s.count)])
  );

  const filterIsActive = (kind) => {
    switch (kind) {
      case 'critical':
        return (activeFilters.severity || '').toUpperCase() === 'CRITICAL';
      case 'high':
        return (activeFilters.severity || '').toUpperCase() === 'HIGH';
      case 'kev':
        return activeFilters.kev === 'true';
      case 'critical_priority':
        return String(activeFilters.min_priority || '') === '80';
      default:
        return false;
    }
  };

  const tiles = [
    {
      label: 'Prodotti monitorati',
      value: stats.product_count,
      accent: 'text-indigo-400',
      kind: 'static',
    },
    {
      label: 'CVE totali',
      value: stats.total_cves?.toLocaleString(),
      accent: 'text-gray-200',
      kind: 'static',
    },
    {
      label: 'Critical',
      value: severity['CRITICAL']?.toLocaleString() || 0,
      accent: 'text-red-400',
      activeBg: 'bg-red-900/30',
      kind: 'critical',
      tooltip: 'Filtra: severità Critical',
    },
    {
      label: 'High',
      value: severity['HIGH']?.toLocaleString() || 0,
      accent: 'text-orange-400',
      activeBg: 'bg-orange-900/30',
      kind: 'high',
      tooltip: 'Filtra: severità High',
    },
    {
      label: 'In CISA KEV',
      value: stats.kev_count?.toLocaleString(),
      accent: 'text-purple-400',
      activeBg: 'bg-purple-900/30',
      kind: 'kev',
      tooltip: 'Filtra: solo CVE in CISA KEV',
    },
    {
      label: 'Priorità Critica',
      value: parseInt(stats.priority_distribution?.critical_priority || 0).toLocaleString(),
      accent: 'text-rose-400',
      activeBg: 'bg-rose-900/30',
      kind: 'critical_priority',
      tooltip: 'Filtra: priority score ≥ 80',
    },
  ];

  function handleClick(kind) {
    if (!onFilter) return;
    const wasActive = filterIsActive(kind);
    switch (kind) {
      case 'critical':
        onFilter({ severity: wasActive ? '' : 'CRITICAL' });
        break;
      case 'high':
        onFilter({ severity: wasActive ? '' : 'HIGH' });
        break;
      case 'kev':
        onFilter({ kev: wasActive ? '' : 'true' });
        break;
      case 'critical_priority':
        onFilter({ min_priority: wasActive ? '' : '80' });
        break;
      default:
        break;
    }
  }

  return (
    <dl
      className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6"
      aria-label="Indicatori sintetici"
    >
      {tiles.map((t) => {
        if (t.kind === 'static') {
          return (
            <div
              key={t.label}
              className="rounded-xl bg-gray-900 border border-gray-800 p-4"
            >
              <dt className="text-xs text-gray-500 mb-1">{t.label}</dt>
              <dd className={`text-2xl font-bold ${t.accent}`}>{t.value ?? '—'}</dd>
            </div>
          );
        }
        const active = filterIsActive(t.kind);
        return (
          <button
            key={t.label}
            type="button"
            onClick={() => handleClick(t.kind)}
            aria-pressed={active}
            title={t.tooltip}
            className={`text-left rounded-xl border p-4 transition group focus:outline-none ${
              active
                ? `${t.activeBg} border-current ${t.accent}`
                : 'bg-gray-900 border-gray-800 hover:border-gray-600 hover:bg-gray-900/80'
            }`}
          >
            <dt className="text-xs text-gray-500 mb-1 group-hover:text-gray-400 flex items-center gap-1">
              {t.label}
              <span aria-hidden className="text-[10px] opacity-50">↗</span>
            </dt>
            <dd className={`text-2xl font-bold ${t.accent}`}>{t.value ?? '—'}</dd>
          </button>
        );
      })}
    </dl>
  );
}
