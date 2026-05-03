'use client';
import { useState, useRef } from 'react';
import { addProduct, addProductsBulk } from '../../lib/api';
import { useEscape, useFocusTrap } from '../../lib/useDialog';

export default function AddProductModal({ onClose, onAdded }) {
  const [tab, setTab] = useState('single');
  const [form, setForm] = useState({ name: '', version: '', vendor: '', cpe_keyword: '' });
  const [bulkText, setBulkText] = useState('');
  const [csvFile, setCsvFile] = useState(null);
  const [csvPreview, setCsvPreview] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef();

  useEscape(onClose);
  const dialogRef = useFocusTrap(true);

  function handleFile(file) {
    if (!file) return;
    setCsvFile(file);
    setError('');
    setResult(null);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target.result;
      const parsed = parseCsv(text);
      if (!parsed.length) setError('Nessun prodotto valido trovato nel CSV');
      setCsvPreview(parsed);
    };
    reader.readAsText(file);
  }

  async function handleSingle(e) {
    e.preventDefault();
    if (!form.name || !form.version) return setError('Nome e versione sono obbligatori');
    setLoading(true); setError('');
    try {
      await addProduct(form);
      onAdded(); onClose();
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally { setLoading(false); }
  }

  async function handleBulk(e) {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      const products = parseTextLines(bulkText);
      if (!products.length) return setError('Formato: nome,versione,vendor (una riga per prodotto)');
      const res = await addProductsBulk(products);
      setResult(res);
      onAdded();
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally { setLoading(false); }
  }

  async function handleCsv(e) {
    e.preventDefault();
    if (!csvPreview.length) return setError('Carica un file CSV prima');
    setLoading(true); setError('');
    try {
      const res = await addProductsBulk(csvPreview);
      setResult(res);
      onAdded();
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally { setLoading(false); }
  }

  function onFileChange(e) {
    handleFile(e.target.files?.[0]);
  }

  function onDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer?.files?.[0];
    handleFile(file);
  }

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
      role="presentation"
      onClick={onClose}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Aggiungi prodotto"
        className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-5 border-b border-gray-800">
          <h2 className="text-base font-semibold text-white">Aggiungi prodotto</h2>
          <button
            onClick={onClose}
            aria-label="Chiudi finestra"
            className="text-gray-400 hover:text-white text-xl px-2 rounded"
          >✕</button>
        </div>

        <div className="flex border-b border-gray-800">
          {[['single','Singolo'], ['bulk','Lista testo'], ['csv','CSV file']].map(([t, label]) => (
            <button
              key={t}
              onClick={() => { setTab(t); setError(''); setResult(null); }}
              className={`flex-1 py-2.5 text-xs font-medium transition ${tab === t ? 'text-indigo-400 border-b-2 border-indigo-500' : 'text-gray-400 hover:text-gray-200'}`}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="p-5">
          {/* ── Singolo ── */}
          {tab === 'single' && (
            <form onSubmit={handleSingle} className="space-y-3">
              <Field label="Nome prodotto *" value={form.name} onChange={v => setForm({...form, name: v})} placeholder="es. Apache Log4j" />
              <Field label="Versione *" value={form.version} onChange={v => setForm({...form, version: v})} placeholder="es. 2.14.1" />
              <Field label="Vendor (opzionale)" value={form.vendor} onChange={v => setForm({...form, vendor: v})} placeholder="es. Apache" />
              <Field label="Keyword NVD (opzionale)" value={form.cpe_keyword} onChange={v => setForm({...form, cpe_keyword: v})} placeholder="es. cpe:2.3:o:microsoft:windows_10_21h2:10.0.19044:*:*:*:*:*:*:*" />
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-2 text-xs text-gray-500 space-y-1">
                <p>Lascia vuoto → usa <code className="text-gray-400">nome + versione</code> come keyword.</p>
                <p>Per OS Windows usa CPE completo, es:</p>
                <button type="button" onClick={() => setForm({...form, cpe_keyword: 'cpe:2.3:o:microsoft:windows_10_21h2:10.0.19044:*:*:*:*:*:*:*'})}
                  className="text-indigo-400 hover:text-indigo-300 font-mono text-xs underline block truncate w-full text-left">
                  cpe:2.3:o:microsoft:windows_10_21h2:10.0.19044:*:*:*:*:*:*:*
                </button>
              </div>
              {error && <p className="text-red-400 text-xs">{error}</p>}
              <button type="submit" disabled={loading} className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white py-2 rounded-lg text-sm font-medium transition">
                {loading ? 'Aggiunta...' : 'Aggiungi e sincronizza'}
              </button>
            </form>
          )}

          {/* ── Lista testo ── */}
          {tab === 'bulk' && !result && (
            <form onSubmit={handleBulk} className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Una riga per prodotto: <code className="text-gray-300">nome,versione,vendor</code></label>
                <textarea
                  value={bulkText}
                  onChange={e => setBulkText(e.target.value)}
                  rows={8}
                  placeholder={"Apache Log4j,2.14.1,Apache\nOpenSSL,1.0.2k,OpenSSL\nNginx,1.18.0,nginx"}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>
              {error && <p className="text-red-400 text-xs">{error}</p>}
              <button type="submit" disabled={loading} className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white py-2 rounded-lg text-sm font-medium transition">
                {loading ? 'Importazione...' : 'Importa tutto'}
              </button>
            </form>
          )}

          {/* ── CSV file ── */}
          {tab === 'csv' && !result && (
            <form onSubmit={handleCsv} className="space-y-4">
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-3 text-xs text-gray-400 space-y-1">
                <p className="font-medium text-gray-300">Formato CSV atteso:</p>
                <p>• Prima colonna: <code className="text-gray-200">nome</code> (obbligatorio)</p>
                <p>• Seconda colonna: <code className="text-gray-200">versione</code> (obbligatorio)</p>
                <p>• Terza colonna: <code className="text-gray-200">vendor</code> (opzionale)</p>
                <p>• Quarta colonna: <code className="text-gray-200">keyword_nvd</code> (opzionale)</p>
                <p className="text-gray-500">L&apos;intestazione (header row) viene ignorata automaticamente se presente.</p>
              </div>

              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    fileRef.current?.click();
                  }
                }}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
                aria-label="Seleziona o trascina file CSV"
                className={`w-full border-2 border-dashed rounded-xl p-6 text-center transition focus:outline-none ${
                  dragOver
                    ? 'border-indigo-500 bg-indigo-950/20'
                    : 'border-gray-700 hover:border-indigo-600'
                }`}
              >
                <input ref={fileRef} type="file" accept=".csv,.txt" onChange={onFileChange} className="hidden" />
                {csvFile ? (
                  <div>
                    <p className="text-sm text-white font-medium">{csvFile.name}</p>
                    <p className="text-xs text-gray-400 mt-1">{csvPreview.length} prodotti pronti all&apos;importazione</p>
                  </div>
                ) : (
                  <div>
                    <p className="text-2xl mb-2" aria-hidden>📂</p>
                    <p className="text-sm text-gray-400">Clicca o trascina il file CSV</p>
                    <p className="text-xs text-gray-600 mt-1">.csv o .txt</p>
                  </div>
                )}
              </button>

              {csvPreview.length > 0 && (
                <div className="max-h-40 overflow-y-auto rounded-lg border border-gray-700">
                  <table className="w-full text-xs">
                    <thead className="bg-gray-800 sticky top-0">
                      <tr>
                        {['Nome','Versione','Vendor'].map(h => (
                          <th key={h} className="text-left px-2 py-1.5 text-gray-400 font-medium">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {csvPreview.slice(0, 20).map((p, i) => (
                        <tr key={i} className="border-t border-gray-800">
                          <td className="px-2 py-1 text-white">{p.name}</td>
                          <td className="px-2 py-1 text-gray-300">{p.version}</td>
                          <td className="px-2 py-1 text-gray-400">{p.vendor || '—'}</td>
                        </tr>
                      ))}
                      {csvPreview.length > 20 && (
                        <tr><td colSpan={3} className="px-2 py-1 text-gray-500 text-center">... e altri {csvPreview.length - 20}</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {error && <p className="text-red-400 text-xs">{error}</p>}
              <button type="submit" disabled={loading || !csvPreview.length} className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white py-2 rounded-lg text-sm font-medium transition">
                {loading ? `Importazione ${csvPreview.length} prodotti...` : `Importa ${csvPreview.length} prodotti`}
              </button>
            </form>
          )}

          {/* ── Risultato bulk/csv ── */}
          {result && (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="bg-green-900/30 border border-green-700 rounded-lg p-3">
                  <div className="text-xl font-bold text-green-400">{result.created?.length || 0}</div>
                  <div className="text-xs text-green-500">Aggiunti</div>
                </div>
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-3">
                  <div className="text-xl font-bold text-gray-400">{result.skipped?.length || 0}</div>
                  <div className="text-xs text-gray-500">Già presenti</div>
                </div>
                <div className="bg-red-900/30 border border-red-700 rounded-lg p-3">
                  <div className="text-xl font-bold text-red-400">{result.errors?.length || 0}</div>
                  <div className="text-xs text-red-500">Errori</div>
                </div>
              </div>
              <p className="text-xs text-gray-400 text-center">La sincronizzazione CVE è partita in background.</p>
              <button onClick={onClose} className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-2 rounded-lg text-sm font-medium transition">
                Chiudi
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, onChange, placeholder }) {
  return (
    <div>
      <label className="text-xs text-gray-400 block mb-1">{label}</label>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
      />
    </div>
  );
}

function parseTextLines(text) {
  return text.trim().split('\n').filter(Boolean).map(line => {
    const parts = line.split(',').map(p => p.trim());
    return { name: parts[0], version: parts[1] || '', vendor: parts[2] || '', cpe_keyword: parts[3] || '' };
  }).filter(p => p.name && p.version);
}

function parseCsv(text) {
  const lines = text.trim().split('\n').filter(Boolean);
  if (!lines.length) return [];

  // Detect and skip header row
  const first = lines[0].toLowerCase();
  const startIdx = (first.includes('nome') || first.includes('name') || first.includes('product')) ? 1 : 0;

  const results = [];
  for (let i = startIdx; i < lines.length; i++) {
    const cols = splitCsvLine(lines[i]);
    const name = cols[0]?.trim();
    const version = cols[1]?.trim();
    if (!name || !version) continue;
    results.push({
      name,
      version,
      vendor: cols[2]?.trim() || '',
      cpe_keyword: cols[3]?.trim() || '',
    });
  }
  return results;
}

function splitCsvLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (const ch of line) {
    if (ch === '"') { inQuotes = !inQuotes; continue; }
    if (ch === ',' && !inQuotes) { result.push(current); current = ''; continue; }
    current += ch;
  }
  result.push(current);
  return result;
}
