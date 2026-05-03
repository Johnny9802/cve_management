'use client';
import { useState } from 'react';
import { updateSystemConfig } from '../../lib/api';

const SOURCE_BADGE = {
  db:    'bg-indigo-900/40 text-indigo-300 border-indigo-700',
  env:   'bg-gray-800 text-gray-400 border-gray-600',
  unset: 'bg-gray-900 text-gray-600 border-gray-700',
};

function Tooltip({ text }) {
  const [show, setShow] = useState(false);
  return (
    <span className="relative ml-1 cursor-help"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      <span className="text-gray-500 hover:text-gray-300 text-xs">ⓘ</span>
      {show && (
        <span className="absolute left-6 top-0 z-30 w-64 bg-gray-800 border border-gray-600 text-gray-200 text-xs rounded-lg p-2 shadow-xl">
          {text}
        </span>
      )}
    </span>
  );
}

function SkeletonRow() {
  return (
    <div className="grid grid-cols-12 gap-4 px-4 py-3 items-center animate-pulse">
      <div className="col-span-3 h-4 bg-gray-700 rounded" />
      <div className="col-span-5 h-8 bg-gray-700 rounded" />
      <div className="col-span-2 h-5 w-10 bg-gray-700 rounded" />
      <div className="col-span-2 h-8 bg-gray-700 rounded" />
    </div>
  );
}

const EPSS_OPTIONS = [
  { value: 'first_org', label: 'FIRST.org v3', desc: 'Fonte ufficiale EPSS (api.first.org) — modello corrente v3, aggiornato quotidianamente' },
  { value: 'vulncheck', label: 'VulnCheck NVD++', desc: 'Score EPSS integrati nei dati VulnCheck — richiede VULNCHECK_API_KEY' },
  { value: 'disabled',  label: 'Disabilitato', desc: 'Non recuperare score EPSS — mostra solo CVSS e KEV per la prioritizzazione' },
];

function EpssProviderRow({ entry, onSave }) {
  const current = entry.value_masked || 'first_org';
  const [selected, setSelected] = useState(current);
  const [saving, setSaving] = useState(false);
  const dirty = selected !== current;

  async function handleSave() {
    setSaving(true);
    try { await onSave(entry.key, selected); }
    finally { setSaving(false); }
  }

  return (
    <div className="px-4 py-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <span className="font-mono text-sm text-gray-200">{entry.key}</span>
          <Tooltip text={entry.description} />
        </div>
        <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SOURCE_BADGE[entry.source]}`}>
          {entry.source.toUpperCase()}
        </span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        {EPSS_OPTIONS.map(opt => (
          <label key={opt.value}
            className={`flex items-start gap-2 p-3 rounded-lg border cursor-pointer transition ${
              selected === opt.value
                ? 'border-indigo-500 bg-indigo-900/20'
                : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
            }`}>
            <input type="radio" name="epss_provider" value={opt.value}
              checked={selected === opt.value}
              onChange={() => setSelected(opt.value)}
              className="mt-0.5 accent-indigo-500" />
            <div>
              <div className="text-sm text-gray-100 font-medium">{opt.label}</div>
              <div className="text-xs text-gray-500 mt-0.5">{opt.desc}</div>
            </div>
          </label>
        ))}
      </div>
      {dirty && (
        <div className="flex justify-end">
          <button onClick={handleSave} disabled={saving}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-4 py-1.5 rounded-lg text-xs font-medium transition">
            {saving ? '…' : 'Salva provider EPSS'}
          </button>
        </div>
      )}
    </div>
  );
}

function ConfigRow({ entry, onSave, onSaved }) {
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState('');
  const dirty = value.trim().length > 0;

  async function handleSave() {
    if (!dirty) return;
    setSaving(true); setErr('');
    try {
      await onSave(entry.key, value.trim());
      setValue('');
      onSaved?.(entry.key);
    } catch (e) {
      setErr(e.response?.data?.error || e.message);
    } finally { setSaving(false); }
  }

  return (
    <div className="grid grid-cols-12 gap-4 px-4 py-3 items-center">
      <div className="col-span-3">
        <span className="font-mono text-sm text-gray-200">{entry.key}</span>
        <Tooltip text={entry.description} />
      </div>
      <div className="col-span-5 space-y-1">
        <input
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSave()}
          placeholder={
            entry.value_masked
              ? entry.value_masked
              : entry.is_set ? '(configurata)' : 'Non configurata — inserisci il valore'
          }
          className="w-full bg-gray-800 border border-gray-700 focus:border-indigo-500 rounded-lg px-3 py-1.5 text-sm text-gray-100 font-mono focus:outline-none transition"
        />
        {err && <p className="text-xs text-red-400">{err}</p>}
      </div>
      <div className="col-span-2">
        <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SOURCE_BADGE[entry.source]}`}>
          {entry.source.toUpperCase()}
        </span>
      </div>
      <div className="col-span-2">
        <button onClick={handleSave} disabled={!dirty || saving}
          className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-3 py-1.5 rounded-lg text-xs font-medium transition">
          {saving ? <span className="animate-spin inline-block">⟳</span> : 'Salva'}
        </button>
      </div>
    </div>
  );
}

export default function ConfigTable({ configs, loading, onRefreshStatus }) {
  const [toast, setToast] = useState('');

  function showToast(msg) {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  }

  async function handleSave(key, value) {
    await updateSystemConfig(key, value);
    showToast(`✓ ${key} salvato`);
    if (key === 'NVD_API_KEY') onRefreshStatus?.();
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden relative">
      {toast && (
        <div className="absolute top-3 right-3 z-10 bg-green-900/80 border border-green-700 text-green-300 text-xs px-3 py-1.5 rounded-lg shadow">
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="grid grid-cols-12 gap-4 px-4 py-2.5 border-b border-gray-800 bg-gray-800/50">
        {['Chiave', 'Nuovo valore', 'Origine', 'Azione'].map((h) => (
          <div key={h} className={`text-xs uppercase text-gray-500 font-medium ${h === 'Chiave' ? 'col-span-3' : h === 'Nuovo valore' ? 'col-span-5' : h === 'Origine' ? 'col-span-2' : 'col-span-2'}`}>
            {h}
          </div>
        ))}
      </div>

      {/* Show skeleton until configs is populated (null = not yet loaded) */}
      {configs === null ? (
        <div className="divide-y divide-gray-800">
          <SkeletonRow />
          <SkeletonRow />
        </div>
      ) : configs.length === 0 ? (
        <p className="text-gray-500 text-sm text-center py-8">Nessuna configurazione disponibile</p>
      ) : (
        <div className="divide-y divide-gray-800">
          {configs.map((entry) =>
            entry.key === 'EPSS_PROVIDER' ? (
              <EpssProviderRow key={entry.key} entry={entry} onSave={handleSave} />
            ) : (
              <ConfigRow key={entry.key} entry={entry} onSave={handleSave} onSaved={() => {}} />
            )
          )}
        </div>
      )}
    </div>
  );
}
