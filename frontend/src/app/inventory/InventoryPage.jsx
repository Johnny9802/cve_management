'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  addProduct,
  addProductsBulk,
  deleteProduct,
  getProducts,
  syncProduct,
} from '../../lib/api';
import { parseCsv } from '../../lib/csv';
import { fmtDate } from '../../lib/utils';

// Heuristic until the backend carries an explicit type column.
// Lower-cased vendor / product names matching one of these tokens are
// classified as OS; everything else is software.
const OS_TOKENS = ['windows', 'linux', 'ubuntu', 'debian', 'rhel', 'centos', 'fedora', 'macos', 'osx', 'ios', 'android'];

function classifyType(p) {
  const hay = `${p.vendor || ''} ${p.name || ''}`.toLowerCase();
  return OS_TOKENS.some((t) => hay.includes(t)) ? 'os' : 'software';
}

const TABS = [
  { key: '',         label: 'Tutto'    },
  { key: 'software', label: 'Software' },
  { key: 'os',       label: 'Sistemi operativi' },
];

export default function InventoryPage() {
  const initialType = () => {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get('type') ?? '';
  };

  const [type, setType] = useState(initialType);
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams();
    if (type) params.set('type', type);
    const qs = params.toString();
    const target = qs ? `?${qs}` : window.location.pathname;
    window.history.replaceState(null, '', target);
  }, [type]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const rows = await getProducts();
      setProducts(rows || []);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = useMemo(() => {
    if (!type) return products;
    return products.filter((p) => classifyType(p) === type);
  }, [products, type]);

  return (
    <div className="space-y-4">
      {/* Empty state with prominent drop-zone */}
      {!loading && products.length === 0 && !error && (
        <CsvDropZone onUploaded={load} prominent />
      )}

      {/* Always-visible upload zone for non-empty inventory */}
      {(loading || products.length > 0) && (
        <details className="bg-gray-900 border border-gray-800 rounded-xl group">
          <summary className="cursor-pointer list-none px-4 py-2.5 text-sm text-gray-300 hover:text-white flex items-center justify-between">
            <span>Importa da CSV</span>
            <span aria-hidden className="text-xs opacity-60 group-open:rotate-180 transition-transform">▾</span>
          </summary>
          <div className="px-4 pb-4">
            <CsvDropZone onUploaded={load} />
          </div>
        </details>
      )}

      {/* Tabs */}
      <div role="tablist" aria-label="Filtra per tipo"
        className="flex gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1">
        {TABS.map((t) => {
          const active = type === t.key;
          return (
            <button
              key={t.key || 'all'}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setType(t.key)}
              className={`text-xs px-3 py-1.5 rounded-lg transition ${
                active ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'
              }`}
            >
              {t.label}
            </button>
          );
        })}
        <span className="ml-auto text-[11px] text-gray-500 self-center pr-2" aria-live="polite">
          {filtered.length} elemento/i
        </span>
      </div>

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-gray-950/50 text-gray-400 uppercase tracking-wide text-[10px]">
            <tr>
              <th className="px-3 py-2 text-left">Nome</th>
              <th className="px-3 py-2 text-left">Vendor</th>
              <th className="px-3 py-2 text-left">Versione</th>
              <th className="px-3 py-2 text-left">Tipo</th>
              <th className="px-3 py-2 text-left">CVE</th>
              <th className="px-3 py-2 text-left">Critical</th>
              <th className="px-3 py-2 text-left">Sync</th>
              <th className="px-3 py-2 text-right">Azioni</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading && filtered.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-600">Caricamento…</td></tr>
            )}
            {!loading && filtered.length === 0 && !error && (
              <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-600 italic">
                Nessun prodotto in questo gruppo.
              </td></tr>
            )}
            {error && (
              <tr><td colSpan={8} className="px-3 py-4 text-center text-red-400">{error}</td></tr>
            )}
            {filtered.map((p) => (
              <ProductRow key={p.id} product={p} onChanged={load} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ProductRow({ product, onChanged }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const t = classifyType(product);

  async function onSync() {
    setBusy(true);
    setMsg('');
    try {
      await syncProduct(product.id);
      setMsg('sync avviato');
      setTimeout(() => { setMsg(''); onChanged?.(); }, 1500);
    } catch (e) {
      setMsg(e?.response?.data?.detail || e?.message || 'errore');
    } finally {
      setBusy(false);
    }
  }
  async function onDelete() {
    if (!confirm(`Eliminare "${product.name} ${product.version}"? I finding collegati saranno eliminati in cascata.`)) return;
    setBusy(true);
    try {
      await deleteProduct(product.id);
      onChanged?.();
    } catch (e) {
      setMsg(e?.response?.data?.detail || e?.message || 'errore');
      setBusy(false);
    }
  }

  return (
    <tr className="hover:bg-gray-800/40">
      <td className="px-3 py-2 text-gray-200">{product.name}</td>
      <td className="px-3 py-2 text-gray-400">{product.vendor || '—'}</td>
      <td className="px-3 py-2 text-gray-300 font-mono">{product.version}</td>
      <td className="px-3 py-2">
        <span className="text-[10px] uppercase tracking-wide text-gray-500 bg-gray-800 border border-gray-700 px-1.5 rounded">{t}</span>
      </td>
      <td className="px-3 py-2 text-gray-300">{product.cve_count ?? 0}</td>
      <td className="px-3 py-2">
        {product.critical_count > 0 ? (
          <span className="text-red-300 font-semibold">{product.critical_count}</span>
        ) : (
          <span className="text-gray-600">0</span>
        )}
      </td>
      <td className="px-3 py-2 text-[11px] text-gray-500">
        {product.sync_status || '—'}
        {product.last_synced_at && (
          <span className="ml-1 text-gray-600">{fmtDate(product.last_synced_at)}</span>
        )}
      </td>
      <td className="px-3 py-2 text-right space-x-1">
        {msg && <span className="text-[10px] text-gray-400 mr-1">{msg}</span>}
        <button type="button" disabled={busy} onClick={onSync}
          className="text-[11px] px-2 py-1 rounded border border-gray-700 hover:bg-gray-800 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-indigo-500">
          Sync
        </button>
        <button type="button" disabled={busy} onClick={onDelete}
          className="text-[11px] px-2 py-1 rounded border border-red-800 text-red-300 hover:bg-red-950/50 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-red-400">
          Elimina
        </button>
      </td>
    </tr>
  );
}

function CsvDropZone({ onUploaded, prominent }) {
  const [parsed, setParsed] = useState([]);
  const [errors, setErrors] = useState([]);
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  function handleFile(file) {
    setError('');
    setResult(null);
    if (!file) return;
    if (file.size > 1024 * 1024) {
      setError('File troppo grande (max 1 MB).');
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const { rows, errors: errs } = parseCsv(String(e.target?.result || ''));
      setParsed(rows);
      setErrors(errs);
    };
    reader.readAsText(file);
  }

  async function onUpload() {
    setBusy(true);
    setError('');
    try {
      const res = await addProductsBulk(parsed);
      setResult(res);
      setParsed([]);
      onUploaded?.();
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2">
      <label
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          handleFile(e.dataTransfer.files?.[0]);
        }}
        className={`block border-2 border-dashed rounded-xl ${
          prominent ? 'p-10' : 'p-6'
        } text-center cursor-pointer transition ${
          drag
            ? 'border-indigo-500 bg-indigo-950/20'
            : 'border-gray-700 hover:border-gray-600 bg-gray-950/40'
        }`}
      >
        <input
          type="file"
          accept=".csv,text/csv"
          onChange={(e) => handleFile(e.target.files?.[0])}
          className="sr-only"
        />
        <p className={`${prominent ? 'text-base' : 'text-sm'} text-gray-300 font-semibold`}>
          Trascina un file CSV qui o click per selezionare
        </p>
        <p className="text-[11px] text-gray-500 mt-1">
          Colonne attese: <code className="font-mono">name, version, vendor, cpe_keyword</code> (header opzionale)
        </p>
      </label>

      {parsed.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded p-3 text-xs space-y-2">
          <p className="text-gray-300">
            <strong>{parsed.length}</strong> righe valide pronte all&apos;import.
            {errors.length > 0 && (
              <span className="text-amber-300 ml-2">{errors.length} righe scartate.</span>
            )}
          </p>
          {errors.length > 0 && (
            <details>
              <summary className="cursor-pointer text-[11px] text-gray-500">
                Mostra righe scartate
              </summary>
              <ul className="text-[10px] text-amber-200 list-disc list-inside mt-1">
                {errors.slice(0, 10).map((err, i) => <li key={i}>{err}</li>)}
                {errors.length > 10 && <li>… e altre {errors.length - 10}</li>}
              </ul>
            </details>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={onUpload}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 text-white text-xs font-semibold px-3 py-1.5 rounded focus:outline-none focus:ring-2 focus:ring-indigo-400"
            >
              {busy ? 'Importazione…' : `Importa ${parsed.length} prodotti`}
            </button>
            <button type="button" onClick={() => { setParsed([]); setErrors([]); }}
              className="text-xs px-3 py-1.5 rounded border border-gray-700 hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-indigo-500">
              Annulla
            </button>
          </div>
        </div>
      )}

      {result && (
        <div className="text-xs text-gray-300 bg-emerald-950/30 border border-emerald-800 rounded p-2">
          Import completato: <strong>{result.created?.length || 0}</strong> creati,
          {' '}<strong>{result.skipped?.length || 0}</strong> già presenti,
          {' '}<strong>{result.errors?.length || 0}</strong> errori.
        </div>
      )}

      {error && (
        <p role="alert" className="text-xs text-red-400">{error}</p>
      )}
    </div>
  );
}
