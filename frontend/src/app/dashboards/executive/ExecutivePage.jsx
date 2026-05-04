'use client';

/**
 * Dashboard A — Executive Risk Overview (Sprint Dashboards 3).
 *
 * Cold-start: with one snapshot the trend chart shows an "in arrivo"
 * empty state. Period selector controls how many days of snapshots
 * are pulled.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import AppShell from '../../../components/Shell/AppShell';
import KpiTrendCard from '../../../components/Executive/KpiTrendCard';
import TrendLineChart from '../../../components/Executive/TrendLineChart';
import AgingBucketChart from '../../../components/Executive/AgingBucketChart';
import ExecPdfButton from '../../../components/Executive/ExecPdfButton';
import { getDashboardExec } from '../../../lib/api';

const PERIODS = [
  { key: 30,  label: '30 gg' },
  { key: 90,  label: '90 gg' },
  { key: 180, label: '180 gg' },
  { key: 365, label: '1 anno' },
];

export default function ExecutivePage() {
  const [periodDays, setPeriodDays] = useState(90);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastRefreshed, setLastRefreshed] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const payload = await getDashboardExec({ period_days: periodDays });
      setData(payload);
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Errore caricamento');
    } finally {
      setLoading(false);
    }
  }, [periodDays]);

  useEffect(() => { load(); }, [load]);

  const series = useMemo(() => data?.snapshots || [], [data]);
  const latest = data?.latest || {};
  const deltas = data?.deltas || {};

  const sparkline = useMemo(() => {
    return {
      risk_score: series.map((s) => Number(s.risk_score) || 0),
      kev:        series.map((s) => Number(s.kev_with_open_finding) || 0),
      open:       series.map((s) => Number(s.findings_open) || 0),
      breached:   series.map((s) => Number(s.findings_breached) || 0),
    };
  }, [series]);

  const periodSelector = (
    <div role="radiogroup" aria-label="Periodo" className="flex bg-gray-800 rounded-lg p-0.5 gap-0.5">
      {PERIODS.map((p) => (
        <button
          key={p.key}
          type="button"
          role="radio"
          aria-checked={periodDays === p.key}
          onClick={() => setPeriodDays(p.key)}
          className={`px-3 py-1 rounded-md text-xs transition ${
            periodDays === p.key
              ? 'bg-indigo-600 text-white'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          {p.label}
        </button>
      ))}
    </div>
  );

  const cold = series.length < 2;

  return (
    <AppShell
      title="Executive Risk Overview"
      subtitle="Postura di sicurezza nel tempo · trend, MTTR, esposizione, velocity"
      onRefresh={load}
      lastRefreshed={lastRefreshed}
      actions={
        <>
          {periodSelector}
          <ExecPdfButton exec={data} periodDays={periodDays} />
        </>
      }
    >
      {error && (
        <div
          className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300"
          role="alert"
        >
          {error}
        </div>
      )}

      {cold && !loading && (
        <div className="bg-amber-950/20 border border-amber-800/60 rounded-xl p-3 text-sm text-amber-200">
          Snapshot disponibili: {series.length}. La dashboard mostra dati significativi a partire da
          2 giorni di snapshot — il job <code className="text-amber-300">daily_snapshot</code> ne cattura
          uno al giorno alle 00:05 UTC. Lo snapshot iniziale viene catturato automaticamente
          all&apos;avvio del backend.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        <KpiTrendCard
          label="Risk score"
          value={latest.risk_score ?? '—'}
          sub="Composito 0-100 (più alto = peggio)"
          delta={deltas.risk_score}
          kind="risk"
          sparkline={sparkline.risk_score}
        />
        <KpiTrendCard
          label="KEV con finding aperto"
          value={latest.kev_with_open_finding ?? '—'}
          sub="Esposizione attiva confermata"
          delta={deltas.kev_with_open_finding}
          kind="risk"
          sparkline={sparkline.kev}
        />
        <KpiTrendCard
          label="Finding open"
          value={latest.findings_open ?? '—'}
          sub="Backlog operativo"
          delta={deltas.findings_open}
          kind="risk"
          sparkline={sparkline.open}
        />
        <KpiTrendCard
          label="SLA breached"
          value={latest.findings_breached ?? '—'}
          sub="Finding oltre il due_date"
          delta={deltas.findings_breached}
          kind="risk"
          sparkline={sparkline.breached}
        />
      </div>

      <TrendLineChart
        title="Trend rischio operativo"
        hint="Critical aperti · KEV con finding · SLA breached negli ultimi giorni"
        data={series}
      />

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <AgingBucketChart buckets={data?.aging_buckets} loading={loading && !data} />

        <section
          aria-label="Velocity remediation"
          className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
        >
          <header className="px-4 py-2.5 border-b border-gray-800">
            <h3 className="text-sm font-semibold text-white">Velocity remediation</h3>
            <p className="text-xs text-gray-500">Finding remediated per settimana, ultime 12 settimane</p>
          </header>
          <div className="p-4">
            {(!data?.velocity_weekly || data.velocity_weekly.length === 0) ? (
              <div className="py-4 text-center text-gray-500 text-sm italic">
                Nessuna remediation negli ultimi 84 giorni.
              </div>
            ) : (
              <ul className="space-y-1.5">
                {data.velocity_weekly.map((v) => {
                  const max = Math.max(1, ...data.velocity_weekly.map((x) => x.remediated_count));
                  const w = Math.round((v.remediated_count / max) * 100);
                  return (
                    <li key={v.week} className="flex items-center gap-2 text-xs">
                      <span className="text-gray-500 font-mono w-20">{v.week}</span>
                      <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                        <div className="h-2 bg-emerald-500" style={{ width: `${w}%` }} aria-hidden />
                      </div>
                      <span className="font-mono text-gray-300 w-8 text-right">{v.remediated_count}</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </section>
      </div>

      <section
        aria-label="Top owners"
        className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
      >
        <header className="px-4 py-2.5 border-b border-gray-800">
          <h3 className="text-sm font-semibold text-white">Top owners (ultimi 90 giorni)</h3>
          <p className="text-xs text-gray-500">Chi sta chiudendo finding e chi ha ancora breach in carico</p>
        </header>
        {(!data?.top_owners || data.top_owners.length === 0) ? (
          <div className="py-4 text-center text-gray-500 text-sm italic">
            Nessun owner con attività recente.
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-500">
                <th className="text-left px-3 py-1.5 font-medium">Owner</th>
                <th className="text-right px-3 py-1.5 font-medium">Remediated</th>
                <th className="text-right px-3 py-1.5 font-medium">Breached</th>
                <th className="text-right px-3 py-1.5 font-medium">Totale</th>
              </tr>
            </thead>
            <tbody>
              {data.top_owners.map((o) => (
                <tr key={o.owner} className="border-t border-gray-800">
                  <td className="px-3 py-1.5 text-gray-200 truncate max-w-[200px]">
                    {o.owner === 'unassigned' ? <span className="text-gray-500 italic">unassigned</span> : o.owner}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-green-300">{o.remediated || 0}</td>
                  <td className={`px-3 py-1.5 text-right font-mono ${o.breached > 0 ? 'text-red-300' : 'text-gray-500'}`}>
                    {o.breached || 0}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-gray-300">{o.total || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </AppShell>
  );
}
