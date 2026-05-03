'use client';
import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { severityBg, fmtDate, fmtScore } from '../../lib/utils';
import ExploitabilityPanel from './Exploitability';

// ─── Constants ───────────────────────────────────────────────
const MODES = [
  { key: 'keyword', label: 'Keyword', hint: 'Testo libero — cerca in tutte le descrizioni CVE su NVD' },
  { key: 'cpe',     label: 'CPE',     hint: 'Nome prodotto → autocomplete CPE → risultati precisi su NVD' },
  { key: 'circl',   label: 'CIRCL',   hint: 'Cerca per Vendor + Prodotto su CIRCL (fonte indipendente da NVD)' },
  { key: 'id',      label: 'CVE ID',  hint: 'Cerca un CVE specifico per ID su NVD' },
  // P6 — Live Exploitability tab. Uses GET /api/cves/{id}/intel?refresh=true.
  { key: 'exploit', label: 'Exploitability', hint: 'PoC pubblici, template Nuclei, KEV ed EPSS via vulnx — dato locale aggiornato on-demand' },
];

const EXAMPLES = {
  keyword: ['apache log4j', 'openssl', 'remote code execution', 'privilege escalation'],
  cpe:     ['windows 10 21h2', 'ubuntu 22.04', 'nginx', 'openssl 3.0'],
  circl:   [{ vendor: 'microsoft', product: 'windows_10' }, { vendor: 'apache', product: 'log4j' }, { vendor: 'linux', product: 'linux_kernel' }],
  id:      ['CVE-2021-44228', 'CVE-2021-34527', 'CVE-2024-3094'],
};

// ─── Debounce hook ────────────────────────────────────────────
function useDebounce(value, delay) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

// ─── Main panel ──────────────────────────────────────────────
export default function LiveSearchPanel({ onSelectCve }) {
  const [mode, setMode]       = useState('keyword');
  const [query, setQuery]     = useState('');
  const [vendor, setVendor]   = useState('');
  const [product, setProduct] = useState('');
  const [severity, setSeverity] = useState('');
  const [year, setYear]       = useState('');   // used by CIRCL filter
  const [from, setFrom]       = useState('');
  const [to, setTo]           = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const [page, setPage]       = useState(1);
  const abortRef = useRef(null);

  // CPE autocomplete state
  const [cpeSuggestions, setCpeSuggestions] = useState([]);
  const [showCpeDrop, setShowCpeDrop] = useState(false);
  const [cpeLoading, setCpeLoading]   = useState(false);
  const debouncedQuery = useDebounce(query, 350);

  // CIRCL product autocomplete
  const [productSuggestions, setProductSuggestions] = useState([]);
  const [showProductDrop, setShowProductDrop] = useState(false);
  const debouncedVendor = useDebounce(vendor, 500);

  // ── CPE autocomplete ──
  useEffect(() => {
    if (mode !== 'cpe' || debouncedQuery.length < 2) {
      setCpeSuggestions([]); setShowCpeDrop(false); return;
    }
    setCpeLoading(true);
    fetch(`/api/cpe-suggest?q=${encodeURIComponent(debouncedQuery)}&limit=12`)
      .then(r => r.json())
      .then(data => { setCpeSuggestions(Array.isArray(data) ? data : []); setShowCpeDrop(true); })
      .catch(() => {})
      .finally(() => setCpeLoading(false));
  }, [debouncedQuery, mode]);

  // ── CIRCL product autocomplete ──
  useEffect(() => {
    if (mode !== 'circl' || debouncedVendor.length < 2) {
      setProductSuggestions([]); setShowProductDrop(false); return;
    }
    fetch(`/api/circl/products?vendor=${encodeURIComponent(debouncedVendor)}`)
      .then(r => r.json())
      .then(data => {
        setProductSuggestions(Array.isArray(data) ? data.slice(0, 15) : []);
        setShowProductDrop(true);
      })
      .catch(() => {});
  }, [debouncedVendor, mode]);

  const daysBetween = (from && to)
    ? Math.round((new Date(to) - new Date(from)) / 86400000)
    : null;

  // ── Search ──
  const search = useCallback(async (p = 1) => {
    if (mode === 'circl' && (!vendor.trim() || !product.trim())) return;
    if (mode !== 'circl' && !query.trim()) return;

    if (abortRef.current) abortRef.current.abort();
    abortRef.current = new AbortController();

    setLoading(true); setError(''); setPage(p);
    setShowCpeDrop(false); setShowProductDrop(false);

    try {
      let url;
      if (mode === 'circl') {
        const params = new URLSearchParams({ vendor: vendor.trim(), product: product.trim(), page: p, limit: 20 });
        if (severity) params.set('severity', severity);
        if (year)     params.set('year', year);
        url = `/api/circl?${params}`;
      } else {
        const params = new URLSearchParams({ page: p, limit: 20 });
        if (mode === 'keyword') params.set('q', query.trim());
        if (mode === 'cpe')     params.set('cpe', query.trim());
        if (mode === 'id')      params.set('id', query.trim());
        if (severity) params.set('severity', severity);
        if (from) params.set('from', from);
        if (to)   params.set('to', to);
        url = `/api/live?${params}`;
      }

      const resp = await fetch(url, { signal: abortRef.current.signal });

      // Safe JSON parse — il server può restituire testo plain in caso di errore
      let data;
      try {
        data = await resp.json();
      } catch {
        throw new Error(`Risposta non valida dal server (HTTP ${resp.status}). Riprova tra qualche secondo.`);
      }

      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      setResults(data);
    } catch (err) {
      if (err.name === 'AbortError') return;
      setError(err.message);
      setResults(null);
    } finally {
      setLoading(false);
    }
  }, [mode, query, vendor, product, severity, year, from, to]);

  function changeMode(m) {
    setMode(m); setQuery(''); setVendor(''); setProduct('');
    setResults(null); setError(''); setShowCpeDrop(false);
    setSeverity(''); setYear(''); setFrom(''); setTo('');
  }

  const currentMode = MODES.find(m => m.key === mode);

  return (
    <div className="space-y-4">

      {/* ── Header / mode selector ── */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-4">
        <div className="flex flex-wrap gap-2 items-start">
          <div role="tablist" aria-label="Modalità ricerca" className="flex bg-gray-800 rounded-lg p-0.5 gap-0.5 overflow-x-auto max-w-full">
            {MODES.map(m => (
              <button
                key={m.key}
                role="tab"
                aria-selected={mode === m.key}
                onClick={() => changeMode(m.key)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition whitespace-nowrap ${
                  mode === m.key ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'
                }`}>
                {m.label}
              </button>
            ))}
          </div>
          <span className="text-xs text-gray-500 self-center ml-1">{currentMode?.hint}</span>
        </div>

        {/* ── Exploitability tab — fully managed by ExploitabilityPanel ── */}
        {mode === 'exploit' && (
          <ExploitabilityPanel onSelectCve={onSelectCve} />
        )}

        {/* ── Input area by mode ── */}
        {(mode === 'keyword' || mode === 'id') && (
          <div className="flex gap-2">
            <input
              value={query} onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && search(1)}
              placeholder={mode === 'keyword' ? 'es. apache log4j, openssl, print spooler…' : 'es. CVE-2021-44228'}
              className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 font-mono"
            />
            <SearchButton onClick={() => search(1)} loading={loading} disabled={!query.trim()} />
          </div>
        )}

        {/* CPE mode with autocomplete */}
        {mode === 'cpe' && (
          <div className="space-y-2">
            <div className="relative">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <input
                    value={query} onChange={e => { setQuery(e.target.value); setResults(null); }}
                    onKeyDown={e => { if (e.key === 'Enter') { setShowCpeDrop(false); search(1); } if (e.key === 'Escape') setShowCpeDrop(false); }}
                    onFocus={() => cpeSuggestions.length > 0 && setShowCpeDrop(true)}
                    placeholder="Digita il nome del prodotto per cercare il CPE…"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
                  />
                  {cpeLoading && (
                    <span className="absolute right-3 top-2.5 text-xs text-gray-500 animate-pulse">…</span>
                  )}
                  {/* CPE dropdown */}
                  {showCpeDrop && cpeSuggestions.length > 0 && (
                    <div className="absolute top-full left-0 right-0 z-20 mt-1 bg-gray-800 border border-gray-700 rounded-lg shadow-xl overflow-hidden max-h-64 overflow-y-auto">
                      {cpeSuggestions.map((s, i) => (
                        <button key={i} onClick={() => { setQuery(s.cpeName); setShowCpeDrop(false); setTimeout(() => search(1), 50); }}
                          className="w-full text-left px-3 py-2.5 hover:bg-gray-700 transition border-b border-gray-700/50 last:border-0">
                          <div className="text-sm text-white font-medium">{s.title}</div>
                          <div className="text-xs font-mono text-indigo-400 truncate mt-0.5">{s.cpeName}</div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <SearchButton onClick={() => { setShowCpeDrop(false); search(1); }} loading={loading} disabled={!query.trim()} />
              </div>
            </div>
            <p className="text-xs text-gray-600">
              Il CPE selezionato viene usato direttamente come filtro NVD — risultati esatti per quel prodotto/versione.
            </p>
            {/* Examples for CPE */}
            <div className="flex flex-wrap gap-1.5">
              <span className="text-xs text-gray-600">Cerca:</span>
              {EXAMPLES.cpe.map(ex => (
                <button key={ex} onClick={() => setQuery(ex)}
                  className="text-xs bg-gray-800 border border-gray-700 hover:border-gray-500 text-gray-400 hover:text-gray-200 px-2 py-0.5 rounded transition">
                  {ex}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* CIRCL mode: vendor + product */}
        {mode === 'circl' && (
          <div className="space-y-2">
            <div className="flex gap-2">
              <div className="flex-1">
                <label className="text-xs text-gray-500 block mb-1">Vendor</label>
                <input
                  value={vendor} onChange={e => { setVendor(e.target.value); setProduct(''); setResults(null); }}
                  onKeyDown={e => e.key === 'Enter' && product && search(1)}
                  placeholder="es. microsoft, apache, linux…"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="flex-1 relative">
                <label className="text-xs text-gray-500 block mb-1">Prodotto</label>
                <input
                  value={product}
                  onChange={e => { setProduct(e.target.value); setResults(null); setShowProductDrop(true); }}
                  onKeyDown={e => { if (e.key === 'Enter') { setShowProductDrop(false); search(1); } if (e.key === 'Escape') setShowProductDrop(false); }}
                  onFocus={() => productSuggestions.length > 0 && setShowProductDrop(true)}
                  placeholder="es. windows_10, log4j…"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
                />
                {showProductDrop && productSuggestions.length > 0 && (
                  <div className="absolute top-full left-0 right-0 z-20 mt-1 bg-gray-800 border border-gray-700 rounded-lg shadow-xl max-h-48 overflow-y-auto">
                    {productSuggestions.map((p, i) => (
                      <button key={i} onClick={() => { setProduct(p); setShowProductDrop(false); }}
                        className="w-full text-left px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 hover:text-white transition border-b border-gray-700/50 last:border-0">
                        {p}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="self-end">
                <SearchButton onClick={() => search(1)} loading={loading} disabled={!vendor.trim() || !product.trim()} />
              </div>
            </div>
            {/* CIRCL examples */}
            <div className="flex flex-wrap gap-1.5 items-center">
              <span className="text-xs text-gray-600">Esempi:</span>
              {EXAMPLES.circl.map(ex => (
                <button key={ex.vendor+ex.product} onClick={() => { setVendor(ex.vendor); setProduct(ex.product); }}
                  className="text-xs bg-gray-800 border border-gray-700 hover:border-gray-500 text-gray-400 hover:text-gray-200 px-2 py-0.5 rounded transition">
                  {ex.vendor}/{ex.product}
                </button>
              ))}
            </div>

            {/* CIRCL filters — filtro in memoria dopo il fetch, non limita il download */}
            <div className="flex gap-2 flex-wrap items-center pt-2 border-t border-gray-800">
              <span className="text-xs text-gray-500">Filtri (applicati in locale):</span>
              <select value={severity} onChange={e => { setSeverity(e.target.value); setResults(null); }}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500">
                <option value="">Tutte le severità</option>
                {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select value={year} onChange={e => { setYear(e.target.value); setResults(null); }}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500">
                <option value="">Tutti gli anni</option>
                {Array.from({ length: 12 }, (_, i) => new Date().getFullYear() - i).map(y => (
                  <option key={y} value={y}>{y}</option>
                ))}
              </select>
              {(severity || year) && (
                <button onClick={() => { setSeverity(''); setYear(''); setResults(null); }}
                  className="text-xs text-gray-500 hover:text-white px-2 py-1.5 border border-gray-700 rounded-lg">
                  ✕ reset
                </button>
              )}
              {(severity || year) && results && (
                <button onClick={() => search(1)}
                  className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-2 py-1.5 rounded-lg transition">
                  ↻ Applica
                </button>
              )}
            </div>
          </div>
        )}

        {/* NVD API limitation notice */}
        {mode === 'keyword' && (from || to) && (
          <div className="flex items-center gap-2 px-3 py-2 bg-amber-950/30 border border-amber-800 rounded-lg text-xs text-amber-300">
            <span>⚠️</span>
            <span>NVD non permette date + keyword nella stessa query — il filtro data è ignorato. Usa CPE o ID per filtrare per data.</span>
          </div>
        )}

        {/* Filters: severity + date (not for CIRCL / ID / Exploitability) */}
        {mode !== 'circl' && mode !== 'id' && mode !== 'exploit' && (
          <div className="flex gap-2 flex-wrap items-center pt-1 border-t border-gray-800">
            <select value={severity} onChange={e => setSeverity(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500">
              <option value="">Tutte le severità</option>
              {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <div className="flex items-center gap-1">
              <span className="text-xs text-gray-500">Dal</span>
              <input type="date" value={from} onChange={e => { setFrom(e.target.value); setResults(null); }}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500" />
            </div>
            <div className="flex items-center gap-1">
              <span className="text-xs text-gray-500">Al</span>
              <input type="date" value={to} onChange={e => { setTo(e.target.value); setResults(null); }}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500" />
            </div>
            {daysBetween !== null && (
              <span className={`text-xs px-2 py-1 rounded border ${
                daysBetween > 360 ? 'text-amber-400 border-amber-700 bg-amber-950/30' :
                daysBetween > 119 ? 'text-blue-400 border-blue-700 bg-blue-950/30' :
                'text-gray-500 border-gray-700'
              }`}>
                {daysBetween}gg
                {daysBetween > 119 && daysBetween <= 360 && ' · chunked'}
                {daysBetween > 360 && ' · richiesta lunga'}
              </span>
            )}
            {(severity || from || to) && (
              <button onClick={() => { setSeverity(''); setFrom(''); setTo(''); setResults(null); }}
                className="text-xs text-gray-500 hover:text-white px-2 py-1.5 border border-gray-700 rounded-lg">
                ✕ reset
              </button>
            )}
          </div>
        )}

        {/* Keyword examples */}
        {(mode === 'keyword') && (
          <div className="flex flex-wrap gap-1.5 items-center">
            <span className="text-xs text-gray-600">Esempi:</span>
            {EXAMPLES.keyword.map(ex => (
              <button key={ex} onClick={() => setQuery(ex)}
                className="text-xs bg-gray-800 border border-gray-700 hover:border-gray-500 text-gray-400 hover:text-gray-200 px-2 py-0.5 rounded transition">
                {ex}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Error — Exploitability panel handles its own errors */}
      {error && mode !== 'exploit' && (
        <div className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300">{error}</div>
      )}

      {/* CIRCL first-load notice */}
      {loading && mode === 'circl' && (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-3 flex items-center gap-2 text-xs text-gray-400">
          <span className="animate-spin">⟳</span>
          Caricamento da CIRCL — recupero tutte le pagine, filtro per severità/anno in locale.
          La prima ricerca può richiedere qualche secondo, le successive sono immediate (cache 1h).
        </div>
      )}

      {/* Results — hidden for the Exploitability tab (it has its own renderer) */}
      {results && mode !== 'exploit' && (
        <ResultsTable
          results={results}
          page={page}
          onPageChange={p => search(p)}
          onRowClick={onSelectCve}
        />
      )}
    </div>
  );
}

// ─── Search button ────────────────────────────────────────────
function SearchButton({ onClick, loading, disabled }) {
  return (
    <button onClick={onClick} disabled={loading || disabled}
      className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white px-5 py-2 rounded-lg text-sm font-medium transition self-end">
      {loading ? <span className="animate-pulse">…</span> : 'Cerca'}
    </button>
  );
}

// ─── Sortable column header ───────────────────────────────────
function SortTh({ label, field, sortKey, sortDir, onSort, align = 'left' }) {
  const active = sortKey === field;
  const arrow = active ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ' ↕';
  return (
    <th
      onClick={() => onSort(field)}
      className={`px-4 py-2.5 font-medium cursor-pointer select-none whitespace-nowrap
        hover:text-white transition text-${align}
        ${active ? 'text-indigo-400' : 'text-gray-500'}`}
    >
      {label}<span className="opacity-60 text-[10px]">{arrow}</span>
    </th>
  );
}

// ─── Results table ────────────────────────────────────────────
function ResultsTable({ results, page, onPageChange, onRowClick }) {
  const [sortKey, setSortKey] = React.useState('published_at');
  const [sortDir, setSortDir] = React.useState('desc');

  function handleSort(field) {
    if (sortKey === field) {
      setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    } else {
      setSortKey(field);
      setSortDir('desc');
    }
  }

  const sorted = useMemo(() => {
    const rows = [...(results.data || [])];
    rows.sort((a, b) => {
      let va = a[sortKey] ?? '';
      let vb = b[sortKey] ?? '';
      // Numeric fields
      if (['cvss_v3_score', 'epss_score', 'priority_score'].includes(sortKey)) {
        va = parseFloat(va) || 0;
        vb = parseFloat(vb) || 0;
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return rows;
  }, [results.data, sortKey, sortDir]);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-400">{results.total?.toLocaleString()} CVE trovati</span>
          {results.source && (
            <span className={`text-xs px-2 py-0.5 rounded border font-medium ${
              results.source === 'CIRCL'
                ? 'bg-teal-900/40 text-teal-300 border-teal-700'
                : 'bg-indigo-900/40 text-indigo-300 border-indigo-700'
            }`}>
              {results.source || 'NVD'}
            </span>
          )}
          {results.chunked && (
            <span className="text-xs text-gray-500">({results.chunks_fetched} chunk)</span>
          )}
          {results.cached && <span className="text-xs text-gray-600">cached</span>}
          <span className="text-xs text-gray-600 italic">
            Ordinamento: {sortKey === 'published_at' ? 'data' : sortKey} {sortDir === 'desc' ? '↓' : '↑'} (in-page)
          </span>
        </div>
        {results.pages > 1 && (
          <div className="flex items-center gap-2 text-xs">
            <button disabled={page <= 1} onClick={() => onPageChange(page - 1)}
              className="px-2 py-1 rounded bg-gray-800 text-gray-300 disabled:opacity-40 hover:bg-gray-700">‹</button>
            <span className="text-gray-400">{page} / {results.pages}</span>
            <button disabled={page >= results.pages} onClick={() => onPageChange(page + 1)}
              className="px-2 py-1 rounded bg-gray-800 text-gray-300 disabled:opacity-40 hover:bg-gray-700">›</button>
          </div>
        )}
      </div>

      {sorted.length === 0 ? (
        <div className="py-10 text-center text-gray-500 text-sm">Nessun risultato.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs">
                <SortTh label="CVE ID"      field="cve_id"        sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
                <th className="text-left px-4 py-2.5 font-medium text-gray-500">Descrizione</th>
                <SortTh label="Severità"    field="severity"      sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
                <SortTh label="CVSS"        field="cvss_v3_score" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
                <SortTh label="EPSS"        field="epss_score"    sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
                <SortTh label="Priority"    field="priority_score" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} align="right" />
                <SortTh label="Pubblicato"  field="published_at"  sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
                <th className="text-center px-4 py-2.5 font-medium text-gray-500">KEV</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map(cve => (
                <tr
                  key={cve.cve_id}
                  onClick={() => onRowClick(cve.cve_id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onRowClick(cve.cve_id);
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`Apri dettaglio ${cve.cve_id}`}
                  className="border-b border-gray-800/60 hover:bg-gray-800/50 cursor-pointer transition focus:outline-none focus:bg-gray-800/70"
                >
                  <td className="px-4 py-2.5 font-mono text-indigo-400 whitespace-nowrap text-xs">{cve.cve_id}</td>
                  <td className="px-4 py-2.5 text-gray-300 max-w-sm">
                    <div className="truncate text-xs" title={cve.description}>{cve.description || '—'}</div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${severityBg(cve.severity)}`}>{cve.severity || '—'}</span>
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-gray-300">{fmtScore(cve.cvss_v3_score)}</td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-gray-300">
                    {cve.epss_score ? `${(parseFloat(cve.epss_score)*100).toFixed(2)}%` : '—'}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <PriorityMini score={cve.priority_score} />
                  </td>
                  <td className="px-4 py-2.5 text-gray-400 whitespace-nowrap text-xs">{fmtDate(cve.published_at)}</td>
                  <td className="px-4 py-2.5 text-center text-xs">{cve.in_cisa_kev ? '🔴' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function PriorityMini({ score }) {
  const s = parseInt(score) || 0;
  let color = 'bg-blue-600';
  if (s >= 80) color = 'bg-red-600';
  else if (s >= 60) color = 'bg-orange-500';
  else if (s >= 40) color = 'bg-yellow-500';
  return (
    <div className="flex items-center gap-1.5 justify-end">
      <span className="text-xs text-gray-400 w-6">{s}</span>
      <div className="w-12 bg-gray-800 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${s}%` }} />
      </div>
    </div>
  );
}
