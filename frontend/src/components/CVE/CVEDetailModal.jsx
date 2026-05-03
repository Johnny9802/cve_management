'use client';
import { useEffect, useState } from 'react';
import { getCveDetail, updateFinding } from '../../lib/api';
import { priorityLabel, fmtDate, fmtScore } from '../../lib/utils';
import { useEscape, useFocusTrap } from '../../lib/useDialog';
import {
  SeverityBadge,
  KevBadge,
  FindingStatusBadge,
  MatchBadge,
} from '../UI/Badge';

export default function CVEDetailModal({ cveId, onClose }) {
  const [cve, setCve] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!cveId) return;
    setLoading(true);
    getCveDetail(cveId)
      .then(setCve)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [cveId]);

  // a11y: Escape closes, focus trap inside modal, focus restored on opener.
  useEscape(onClose);
  const dialogRef = useFocusTrap(!!cveId);

  if (!cveId) return null;

  return (
    <div
      className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4"
      onClick={onClose}
      role="presentation"
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Dettaglio ${cveId}`}
        className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {loading ? (
          <div className="flex items-center justify-center py-16 text-gray-400">Caricamento…</div>
        ) : !cve ? (
          <div className="flex items-center justify-center py-16 text-gray-400">CVE non trovato</div>
        ) : (
          <>
            <div className="flex items-start justify-between p-6 border-b border-gray-800">
              <div>
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <h2 className="text-lg font-bold font-mono text-indigo-400">{cve.cve_id}</h2>
                  <SeverityBadge severity={cve.severity} />
                  {cve.in_cisa_kev && <KevBadge active />}
                </div>
                <p className="text-sm text-gray-300 leading-relaxed max-w-2xl">{cve.description}</p>
              </div>
              <button
                onClick={onClose}
                aria-label="Chiudi dettaglio CVE"
                className="text-gray-400 hover:text-white text-xl ml-4 shrink-0 px-2 rounded"
              >✕</button>
            </div>

            <div className="p-6 space-y-6">
              {/* Scores */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <ScoreCard label="CVSS v3" value={fmtScore(cve.cvss_v3_score)} sub={cve.cvss_v3_vector?.split('/').slice(0,1).join('') || ''} color="text-orange-400" />
                <ScoreCard label="EPSS" value={cve.epss_score != null ? `${(parseFloat(cve.epss_score)*100).toFixed(2)}%` : '—'} sub={cve.epss_percentile != null ? `${(parseFloat(cve.epss_percentile)*100).toFixed(0)}° percentile` : ''} color="text-cyan-400" />
                <PriorityCard score={cve.priority_score} />
                <ScoreCard label="Pubblicato" value={fmtDate(cve.published_at)} sub={`Mod: ${fmtDate(cve.last_modified_at)}`} color="text-gray-300" />
              </div>

              {/* Priority explanation */}
              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
                <h4 className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide">Come è calcolato il Priority Score</h4>
                <PriorityBreakdown cve={cve} />
              </div>

              {/* CISA KEV details */}
              {cve.in_cisa_kev && cve.cisa_kev_date_added && (
                <div className="bg-purple-950/30 border border-purple-800 rounded-xl p-4">
                  <h4 className="text-xs font-semibold text-purple-400 mb-2 uppercase tracking-wide">CISA KEV — Sfruttamento attivo confermato</h4>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div><span className="text-gray-400">Aggiunto: </span><span className="text-white">{fmtDate(cve.cisa_kev_date_added)}</span></div>
                    {cve.cisa_kev_due_date && <div><span className="text-gray-400">Scadenza patch: </span><span className="text-white">{fmtDate(cve.cisa_kev_due_date)}</span></div>}
                  </div>
                </div>
              )}

              {/* Affected products + finding status */}
              {cve.affected_products?.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Prodotti interessati nei tuoi asset</h4>
                  {cve.affected_products.map((p) => (
                    <FindingPanel key={p.id} product={p} cveId={cve.cve_id} />
                  ))}
                </div>
              )}

              {/* Weaknesses */}
              {cve.weaknesses?.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide">Debolezze (CWE)</h4>
                  <div className="flex flex-wrap gap-2">
                    {cve.weaknesses.map((w) => (
                      <span key={w} className="text-xs bg-gray-800 border border-gray-700 px-2 py-1 rounded font-mono text-gray-300">{w}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* References — support both cve_references (DB) and references (NVD live) */}
              {(cve.cve_references?.length > 0 || cve.references?.length > 0) && (
                <div>
                  <h4 className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide">Riferimenti</h4>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {(cve.cve_references || cve.references || []).slice(0, 15).map((r, i) => (
                      <a
                        key={i}
                        href={r.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block text-xs text-indigo-400 hover:text-indigo-300 truncate"
                      >
                        {r.url}
                        {r.tags?.length > 0 && <span className="ml-2 text-gray-500">[{r.tags.join(', ')}]</span>}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function ScoreCard({ label, value, sub, color }) {
  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-3">
      <div className="text-xs text-gray-500 mb-1">{label}</div>
      <div className={`text-xl font-bold ${color}`}>{value}</div>
      {sub && <div className="text-xs text-gray-500 mt-0.5 truncate">{sub}</div>}
    </div>
  );
}

function PriorityCard({ score }) {
  const s = parseInt(score) || 0;
  const { text, cls } = priorityLabel(s);
  return (
    <div className={`rounded-xl p-3 border ${cls}`}>
      <div className="text-xs opacity-70 mb-1">Priority Score</div>
      <div className="text-xl font-bold">{s}/100</div>
      <div className="text-xs opacity-70 mt-0.5">{text}</div>
    </div>
  );
}

function PriorityBreakdown({ cve }) {
  const epss = parseFloat(cve.epss_score) || 0;
  const cvss = parseFloat(cve.cvss_v3_score) || 0;
  const epssContrib = Math.round(epss * 40);

  let cvssContrib = 0;
  if (cve.severity === 'CRITICAL' || cvss >= 9.0) cvssContrib = 25;
  else if (cve.severity === 'HIGH' || cvss >= 7.0) cvssContrib = 18;
  else if (cve.severity === 'MEDIUM' || cvss >= 4.0) cvssContrib = 10;
  else if (cvss > 0) cvssContrib = 4;

  const kevContrib = cve.in_cisa_kev ? 25 : 0;

  let recencyContrib = 0;
  if (cve.published_at) {
    const ageDays = (Date.now() - new Date(cve.published_at).getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays <= 30) recencyContrib = 10;
    else if (ageDays <= 90) recencyContrib = 6;
    else if (ageDays <= 365) recencyContrib = 3;
  }

  const items = [
    { label: `EPSS ${(epss * 100).toFixed(2)}% — probabilità exploit nei prossimi 30gg`, contrib: epssContrib, max: 40 },
    { label: `CVSS ${fmtScore(cvss)} — severità tecnica (${cve.severity})`, contrib: cvssContrib, max: 25 },
    { label: 'CISA KEV — sfruttamento attivo confermato', contrib: kevContrib, max: 25 },
    { label: 'Recency — CVE recente', contrib: recencyContrib, max: 10 },
  ];

  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div key={item.label} className="flex items-center gap-3">
          <div className="text-xs text-gray-400 w-80 truncate">{item.label}</div>
          <div className="flex items-center gap-1.5 flex-1">
            <div className="flex-1 bg-gray-700 rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full ${item.contrib >= item.max ? 'bg-indigo-500' : 'bg-indigo-800'}`}
                style={{ width: `${(item.contrib / item.max) * 100}%` }}
              />
            </div>
            <span className="text-xs text-gray-300 w-12 text-right">+{item.contrib}/{item.max}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

const STATUS_OPTIONS = ['open','in_review','false_positive','accepted_risk','planned','remediated','closed'];
const STATUS_COLORS = {
  open:           'text-gray-300 border-gray-600',
  in_review:      'text-blue-300 border-blue-700',
  false_positive: 'text-gray-400 border-gray-600',
  accepted_risk:  'text-yellow-300 border-yellow-700',
  planned:        'text-indigo-300 border-indigo-700',
  remediated:     'text-green-300 border-green-700',
  closed:         'text-green-400 border-green-600',
};

function FindingPanel({ product, cveId }) {
  const [status, setStatus] = useState(product.status || 'open');
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState('');
  const [savedFlash, setSavedFlash] = useState(false);

  async function changeStatus(newStatus) {
    if (newStatus === status || saving) return;
    setSaving(true); setErr('');
    try {
      await updateFinding(product.id, cveId, { status: newStatus, actor: 'ui' });
      setStatus(newStatus);
      setSavedFlash(true);
      setTimeout(() => setSavedFlash(false), 1500);
    } catch (e) {
      setErr(e.response?.data?.error || e.message);
    } finally { setSaving(false); }
  }

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-3 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-white font-medium">{product.name} {product.version}</span>
          {product.vendor && <span className="text-xs text-gray-500">{product.vendor}</span>}
          {product.match_confidence && <MatchBadge confidence={product.match_confidence} />}
          <FindingStatusBadge status={status} />
          {savedFlash && (
            <span className="text-xs text-green-400" role="status">Salvato</span>
          )}
        </div>
        <div className="flex items-center gap-1 flex-wrap" role="group" aria-label="Cambio stato finding">
          {STATUS_OPTIONS.map((s) => {
            const active = status === s;
            return (
              <button
                key={s}
                disabled={saving}
                onClick={() => changeStatus(s)}
                aria-pressed={active}
                aria-label={`Imposta stato a ${s.replace('_', ' ')}`}
                className={`text-xs px-2 py-0.5 rounded border transition disabled:opacity-40 ${
                  active
                    ? `${STATUS_COLORS[s]} bg-gray-700 font-medium`
                    : 'text-gray-500 border-gray-700 hover:text-gray-300'
                }`}
              >
                {s.replace('_', ' ')}
              </button>
            );
          })}
        </div>
      </div>
      {err && <p className="text-xs text-red-400" role="alert">{err}</p>}
    </div>
  );
}
