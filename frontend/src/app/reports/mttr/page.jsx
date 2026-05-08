'use client';

/**
 * MTTR report page (Sprint 2 — S2.3).
 *
 * Period selector + card per severity. Reuses /api/findings/mttr.
 */
import { useCallback, useEffect, useState } from 'react';
import AppShell from '../../../components/Shell/AppShell';
import { getMttr } from '../../../lib/api';

const PERIODS = [
  { key: '30d', label: '30 gg' },
  { key: '90d', label: '90 gg' },
  { key: '180d', label: '180 gg' },
];

const SEV = [
  { key: 'critical_days', label: 'CRITICAL', color: 'border-red-700 text-red-300' },
  { key: 'high_days',     label: 'HIGH',     color: 'border-orange-700 text-orange-300' },
  { key: 'medium_days',   label: 'MEDIUM',   color: 'border-yellow-700 text-yellow-300' },
  { key: 'low_days',      label: 'LOW',      color: 'border-blue-700 text-blue-300' },
];

export const dynamic = 'force-dynamic';

export default function Page() {
  const [period, setPeriod] = useState('90d');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await getMttr({ period });
      setData(res);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setLoading(false);
    }
  }, [period]);

  useEffect(() => { load(); }, [load]);

  return (
    <AppShell title="MTTR" subtitle="Mean Time to Remediate per severità" onRefresh={load}>
      {error && (
        <div role="alert" className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-500">Periodo:</span>
        <div role="radiogroup" className="flex bg-gray-800 rounded-lg p-0.5 gap-0.5">
          {PERIODS.map((p) => (
            <button
              key={p.key}
              type="button"
              role="radio"
              aria-checked={period === p.key}
              onClick={() => setPeriod(p.key)}
              className={`px-3 py-1 rounded-md text-xs transition ${
                period === p.key ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {SEV.map((s) => {
          const value = data?.[s.key];
          return (
            <div key={s.key} className={`bg-gray-900 border ${s.color} rounded-xl p-4`}>
              <p className="text-[10px] uppercase tracking-wide text-gray-500">{s.label}</p>
              <p className="text-2xl font-bold mt-1">
                {loading ? '…' : value != null ? `${Number(value).toFixed(1)}d` : '—'}
              </p>
              <p className="text-[11px] text-gray-500 mt-1">media giorni open → remediated</p>
            </div>
          );
        })}
      </div>

      {data?.sample_size != null && (
        <p className="text-[11px] text-gray-600">
          Campione: {data.sample_size} finding remediated nel periodo.
        </p>
      )}
    </AppShell>
  );
}
