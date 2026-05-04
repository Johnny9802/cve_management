'use client';

/**
 * Dashboard D — Remediation & Governance (Sprint Dashboards 2).
 *
 * Composition (each panel maps to a real backend endpoint):
 *   • FindingsPipeline       ← /api/dashboard/remediation (pipeline + findings)
 *   • SlaSummaryMatrix       ← /api/findings/sla/summary  +  /api/findings/mttr
 *   • RiskAcceptanceLifecycle ← /api/risk-acceptances/summary
 *   • OwnerWorkloadTable     ← /api/dashboard/owner-workload
 *   • AuditTimeline          ← /api/dashboard/remediation (audit_recent)
 *   • GovernanceExportPanel  ← /api/findings/sla + /api/audit-log (CSV)
 */
import { useCallback, useEffect, useState } from 'react';
import AppShell from '../../../components/Shell/AppShell';
import FindingsPipeline from '../../../components/Remediation/FindingsPipeline';
import SlaSummaryMatrix from '../../../components/Remediation/SlaSummaryMatrix';
import RiskAcceptanceLifecycle from '../../../components/Remediation/RiskAcceptanceLifecycle';
import OwnerWorkloadTable from '../../../components/Remediation/OwnerWorkloadTable';
import AuditTimeline from '../../../components/Remediation/AuditTimeline';
import GovernanceExportPanel from '../../../components/Remediation/GovernanceExportPanel';
import CVEDetailModal from '../../../components/CVE/CVEDetailModal';
import {
  getDashboardRemediation,
  getOwnerWorkload,
  getRiskAcceptanceSummary,
  getSlaSummary,
  getMttr,
} from '../../../lib/api';

export default function RemediationPage() {
  const [remediation, setRemediation] = useState(null);
  const [ownerWorkload, setOwnerWorkload] = useState(null);
  const [riskSummary, setRiskSummary] = useState(null);
  const [slaSummary, setSlaSummary] = useState(null);
  const [mttr, setMttr] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [selectedCve, setSelectedCve] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [r, o, ra, ss, m] = await Promise.allSettled([
        getDashboardRemediation({ audit_limit: 50 }),
        getOwnerWorkload(),
        getRiskAcceptanceSummary({ expiring_window_days: 7 }),
        getSlaSummary(),
        getMttr({ period: '90d' }),
      ]);
      if (r.status === 'fulfilled') setRemediation(r.value);
      if (o.status === 'fulfilled') setOwnerWorkload(o.value);
      if (ra.status === 'fulfilled') setRiskSummary(ra.value);
      if (ss.status === 'fulfilled') setSlaSummary(ss.value);
      if (m.status === 'fulfilled') setMttr(m.value);

      // Surface ONE error if all calls failed; partial failures are tolerated.
      const allFailed = [r, o, ra, ss, m].every((p) => p.status !== 'fulfilled');
      if (allFailed) {
        const firstErr = [r, o, ra, ss, m].find((p) => p.status === 'rejected');
        setError(firstErr?.reason?.message || 'Errore di rete');
      }
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err?.message || 'Errore inatteso');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function handleSelectFinding({ cve_id }) {
    setSelectedCve(cve_id);
  }

  return (
    <AppShell
      title="Remediation & Governance"
      subtitle="Pipeline finding · SLA · accettazioni rischio · audit log · export"
      onRefresh={load}
      lastRefreshed={lastRefreshed}
    >
      {error && (
        <div
          className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300"
          role="alert"
        >
          {error}
        </div>
      )}

      <FindingsPipeline
        pipeline={remediation?.pipeline}
        findings={remediation?.findings || []}
        loading={loading && !remediation}
        onSelectCve={setSelectedCve}
        onChange={load}
      />

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <SlaSummaryMatrix
          summary={slaSummary}
          mttr={mttr}
          loading={loading && !slaSummary}
        />
        <RiskAcceptanceLifecycle
          summary={riskSummary}
          loading={loading && !riskSummary}
          onSelectFinding={handleSelectFinding}
        />
      </div>

      <OwnerWorkloadTable
        owners={ownerWorkload?.owners || []}
        loading={loading && !ownerWorkload}
      />

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <AuditTimeline
          events={remediation?.audit_recent || []}
          loading={loading && !remediation}
          total={remediation?.audit_recent?.length}
        />
        <GovernanceExportPanel />
      </div>

      {selectedCve && (
        <CVEDetailModal cveId={selectedCve} onClose={() => setSelectedCve(null)} />
      )}
    </AppShell>
  );
}
