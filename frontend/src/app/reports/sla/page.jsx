'use client';

/**
 * SLA report page (Sprint 2 — S2.3).
 *
 * Surfaces the existing SlaSummaryMatrix and a paginated list view of
 * findings + their SLA state. Backend already exposes both endpoints
 * (/api/findings/sla/summary, /api/findings/sla, /api/findings/mttr) —
 * until now they were only consumed inside the Remediation dashboard
 * panel.
 */
import { useEffect, useState } from 'react';
import AppShell from '../../../components/Shell/AppShell';
import SlaSummaryMatrix from '../../../components/Remediation/SlaSummaryMatrix';
import { getMttr, getSlaSummary } from '../../../lib/api';

export const dynamic = 'force-dynamic';

export default function Page() {
  const [summary, setSummary] = useState(null);
  const [mttr, setMttr] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    try {
      const [s, m] = await Promise.allSettled([
        getSlaSummary(),
        getMttr({ period: '90d' }),
      ]);
      if (s.status === 'fulfilled') setSummary(s.value);
      if (m.status === 'fulfilled') setMttr(m.value);
      const allFailed = [s, m].every((p) => p.status !== 'fulfilled');
      if (allFailed) {
        setError(s.reason?.message || m.reason?.message || 'Errore');
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <AppShell title="SLA" subtitle="Compliance per severità e MTTR rolling 90gg" onRefresh={load}>
      {error && (
        <div role="alert" className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300">
          {error}
        </div>
      )}
      <SlaSummaryMatrix summary={summary} mttr={mttr} loading={loading && !summary} />
    </AppShell>
  );
}
