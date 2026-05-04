'use client';

/**
 * Dashboard B — SOC Prioritization (Sprint Dashboards 1).
 *
 * Composition:
 *   - GlobalFilterBar (URL-driven chips)
 *   - 4 panels driven by /api/dashboard/triage
 *
 * The page intentionally fetches a single aggregator endpoint so the
 * 4 panels stay consistent and the network footprint is one request.
 * Refreshes manually + every 60s (poll); each refresh is announced via
 * `lastRefreshed` to the AppShell topbar.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import AppShell from '../../../components/Shell/AppShell';
import GlobalFilterBar from '../../../components/Shell/GlobalFilterBar';
import TriagePanel from '../../../components/Triage/TriagePanel';
import CVEDetailModal from '../../../components/CVE/CVEDetailModal';
import { useUrlState } from '../../../lib/url-state';
import { getDashboardTriage } from '../../../lib/api';

const FILTER_DEFAULTS = {
  keyword:        '',
  kev:            '',   // 'true' | 'false' | ''
  has_poc:        '',
  has_nuclei:     '',
  min_epss:       '',   // '0.5' | '0.9' | ''
  min_priority:   '',   // '80' | '60' | '40' | ''
  severity:       '',
};

// Map URL filters → /api/dashboard/triage server-side params. Only
// `keyword` is an explicit aggregator parameter — the rest stay on the
// /api/cves filter chips reused by Sprint Dashboards 2 (Remediation).
function paramsForTriage(filters) {
  return {
    limit_per_panel: 8,
    keyword: filters.keyword || undefined,
  };
}

export default function TriagePage() {
  const [filters, setFilters, resetFilters] = useUrlState(FILTER_DEFAULTS);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [selectedCve, setSelectedCve] = useState(null);
  const inFlight = useRef(false);

  const load = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setLoading(true);
    setError('');
    try {
      const payload = await getDashboardTriage(paramsForTriage(filters));
      setData(payload);
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Errore caricamento');
    } finally {
      setLoading(false);
      inFlight.current = false;
    }
    // We deliberately depend only on `keyword` because the other chips
    // do not change the aggregator response — they re-filter the same
    // panels client-side (they will drive Sprint Dashboards 2's pages).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.keyword]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, [load]);

  // Apply chip filters in the browser (fast, no network) on top of the
  // aggregator response. This way "KEV only" or "PoC only" feels
  // instant when the analyst clicks a chip.
  const filterRows = useCallback((rows) => {
    if (!rows) return [];
    return rows.filter((c) => {
      if (filters.severity && (c.severity || '').toUpperCase() !== filters.severity.toUpperCase()) return false;
      if (filters.kev === 'true' && !c.in_cisa_kev) return false;
      if (filters.kev === 'false' && c.in_cisa_kev) return false;
      if (filters.has_poc === 'true' && !c.has_public_poc) return false;
      if (filters.has_nuclei === 'true' && !c.has_nuclei_template) return false;
      if (filters.min_epss && (c.epss_score == null || parseFloat(c.epss_score) < parseFloat(filters.min_epss))) return false;
      if (filters.min_priority && (c.priority_score == null || parseInt(c.priority_score) < parseInt(filters.min_priority))) return false;
      return true;
    });
  }, [filters]);

  const top      = filterRows(data?.top_urgent);
  const newExpl  = filterRows(data?.new_exploitability);
  const aging    = filterRows(data?.aging_kev);
  const hotlist  = filterRows(data?.epss_hotlist);

  return (
    <AppShell
      title="SOC Triage"
      subtitle="Cosa correggere subito: top priority, nuova exploitability, KEV invecchianti, EPSS in salita"
      onRefresh={load}
      lastRefreshed={lastRefreshed}
    >
      <GlobalFilterBar
        defaults={FILTER_DEFAULTS}
        state={filters}
        setState={setFilters}
        reset={resetFilters}
      />

      {error && (
        <div className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300" role="alert">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <TriagePanel
          title="Top urgenze"
          hint="Priority score più alto sull'intero catalogo"
          rows={top}
          loading={loading && !data}
          accent="red"
          onSelectCve={setSelectedCve}
          highlightField="epss"
          emptyText="Nessuna CVE corrisponde ai filtri attivi."
        />

        <TriagePanel
          title="Nuova exploitability (7gg)"
          hint="CVE con PoC pubblico o template Nuclei comparso di recente"
          rows={newExpl}
          loading={loading && !data}
          accent="violet"
          onSelectCve={setSelectedCve}
          highlightField="exploitability_updated_at"
          emptyText="Nessun cambiamento PoC/Nuclei nei dati attuali — vulnx_refresh non ha (ancora) trovato segnali."
        />

        <TriagePanel
          title="KEV in invecchiamento"
          hint="In CISA KEV da più di 3 giorni"
          rows={aging}
          loading={loading && !data}
          accent="amber"
          onSelectCve={setSelectedCve}
          highlightField="days_in_kev"
          emptyText="Nessun KEV invecchiato fra i risultati attuali."
        />

        <TriagePanel
          title="EPSS hotlist (no KEV)"
          hint="Probabilità di sfruttamento ≥ 0.9 ma non ancora in KEV: candidati alla patch preventiva"
          rows={hotlist}
          loading={loading && !data}
          accent="cyan"
          onSelectCve={setSelectedCve}
          highlightField="epss"
          emptyText="Nessuna CVE hot-EPSS al di fuori di KEV: KEV sta intercettando le minacce."
        />
      </div>

      {selectedCve && (
        <CVEDetailModal cveId={selectedCve} onClose={() => setSelectedCve(null)} />
      )}
    </AppShell>
  );
}
