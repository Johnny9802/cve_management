'use client';
import { useState } from 'react';

const STATUS_CFG = {
  ok:       { label: 'OK',       cls: 'bg-green-900/40 text-green-300 border-green-700' },
  degraded: { label: 'DEGRADED', cls: 'bg-yellow-900/40 text-yellow-300 border-yellow-700' },
  error:    { label: 'ERROR',    cls: 'bg-red-900/40 text-red-300 border-red-700' },
  unknown:  { label: 'UNKNOWN',  cls: 'bg-gray-800 text-gray-400 border-gray-600' },
};

const API_META = {
  nvd:      { icon: '🔵', name: 'NVD',         desc: 'nvd.nist.gov' },
  circl:    { icon: '🟣', name: 'CIRCL',        desc: 'cve.circl.lu' },
  epss:     { icon: '🟡', name: 'EPSS',         desc: 'api.first.org' },
  kev:      { icon: '🔴', name: 'CISA KEV',     desc: 'cisa.gov' },
  redis:    { icon: '🟠', name: 'Redis',         desc: 'Cache interna' },
  database: { icon: '🟢', name: 'Database',      desc: 'PostgreSQL' },
};

export default function ApiStatusCard({ id, data, onTest }) {
  const [testing, setTesting] = useState(false);
  const meta   = API_META[id] || { icon: '⚪', name: id, desc: '' };
  const status = data?.status || 'unknown';
  const cfg    = STATUS_CFG[status] || STATUS_CFG.unknown;

  async function handleTest() {
    setTesting(true);
    try { await onTest(id); }
    finally { setTesting(false); }
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-lg" aria-hidden>{meta.icon}</span>
          <div>
            <div className="text-sm font-medium text-gray-100">{meta.name}</div>
            <div className="text-xs text-gray-500">{meta.desc}</div>
          </div>
        </div>
        <span
          className={`text-xs px-2 py-0.5 rounded border font-medium ${cfg.cls}`}
          aria-label={`${meta.name}: ${cfg.label}${data?.latency_ms != null ? `, ${data.latency_ms}ms` : ''}`}
        >
          {cfg.label}
        </span>
      </div>

      <div className="flex items-end justify-between">
        <div>
          {data?.latency_ms != null ? (
            <span className="text-2xl font-bold text-gray-100">{data.latency_ms}<span className="text-sm text-gray-500 ml-1">ms</span></span>
          ) : (
            <span className="text-sm text-gray-500">—</span>
          )}
          {data?.detail && (
            <div className="text-xs text-red-300 mt-0.5 line-clamp-2">{data.detail}</div>
          )}
        </div>
        <button
          onClick={handleTest}
          disabled={testing}
          aria-busy={testing}
          className="text-xs bg-gray-800 hover:bg-gray-700 border border-gray-600 text-indigo-400 px-3 py-1.5 rounded-lg transition disabled:opacity-40"
        >
          {testing ? <span className="animate-spin inline-block">⟳</span> : 'Test'}
        </button>
      </div>
    </div>
  );
}
