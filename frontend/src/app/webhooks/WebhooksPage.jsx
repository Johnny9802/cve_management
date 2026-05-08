'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  createWebhook,
  deleteWebhook,
  listWebhookDeliveries,
  listWebhooks,
  testWebhook,
  updateWebhook,
} from '../../lib/api';
import { fmtDate } from '../../lib/utils';

const ALL_EVENTS = [
  'finding.created_high_priority',
  'finding.kev',
  'finding.status_changed',
  'risk_acceptance.requested',
  'risk_acceptance.approved',
];

export default function WebhooksPage() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState(null); // null | 'new' | <hook>
  const [openDeliveries, setOpenDeliveries] = useState(null); // hook id

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const payload = await listWebhooks();
      setItems(payload?.data || []);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-xs text-gray-500">
          {items.length} webhook configurati. Le risposte HTTP includono
          un <code className="text-indigo-300">X-Signature</code> HMAC-SHA256
          per la verifica lato consumer.
        </p>
        <button
          type="button"
          onClick={() => setEditing('new')}
          className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold px-3 py-1.5 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-400"
        >
          + Nuovo webhook
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-gray-950/50 text-gray-400 uppercase tracking-wide text-[10px]">
            <tr>
              <th className="px-3 py-2 text-left">Nome</th>
              <th className="px-3 py-2 text-left">URL</th>
              <th className="px-3 py-2 text-left">Eventi</th>
              <th className="px-3 py-2 text-left">Min priority</th>
              <th className="px-3 py-2 text-left">Stato</th>
              <th className="px-3 py-2 text-left">Creato</th>
              <th className="px-3 py-2 text-right">Azioni</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading && items.length === 0 && (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-gray-600">Caricamento…</td></tr>
            )}
            {!loading && items.length === 0 && !error && (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-gray-600 italic">
                Nessun webhook configurato. Crea il primo con il pulsante in alto.
              </td></tr>
            )}
            {error && (
              <tr><td colSpan={7} className="px-3 py-4 text-center text-red-400">{error}</td></tr>
            )}
            {items.map((w) => (
              <WebhookRow
                key={w.id}
                hook={w}
                onEdit={() => setEditing(w)}
                onDeliveries={() => setOpenDeliveries(w.id)}
                onChanged={load}
              />
            ))}
          </tbody>
        </table>
      </div>

      {editing && (
        <WebhookFormDrawer
          hook={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); load(); }}
        />
      )}
      {openDeliveries && (
        <DeliveriesDrawer
          hookId={openDeliveries}
          onClose={() => setOpenDeliveries(null)}
        />
      )}
    </div>
  );
}

function WebhookRow({ hook, onEdit, onDeliveries, onChanged }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  async function onTest() {
    setBusy(true);
    setMsg('');
    try {
      const r = await testWebhook(hook.id);
      setMsg(`OK ${r?.status_code ?? ''}`.trim());
    } catch (e) {
      setMsg(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setBusy(false);
      setTimeout(() => setMsg(''), 4000);
    }
  }

  async function onDelete() {
    if (!confirm(`Eliminare il webhook "${hook.name}"?`)) return;
    setBusy(true);
    try {
      await deleteWebhook(hook.id);
      onChanged?.();
    } catch (e) {
      setMsg(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr className="hover:bg-gray-800/40">
      <td className="px-3 py-2 text-gray-200">{hook.name}</td>
      <td className="px-3 py-2 text-gray-400 truncate max-w-[20ch]" title={hook.url}>{hook.url}</td>
      <td className="px-3 py-2 text-gray-500">
        <span className="text-[10px]">{(hook.event_types || []).length} evento/i</span>
      </td>
      <td className="px-3 py-2 text-gray-400">{hook.min_priority ?? 0}</td>
      <td className="px-3 py-2">
        {hook.enabled ? (
          <span className="text-[10px] text-emerald-300 bg-emerald-950/40 border border-emerald-800 px-1.5 rounded">enabled</span>
        ) : (
          <span className="text-[10px] text-gray-500 bg-gray-800 border border-gray-700 px-1.5 rounded">disabled</span>
        )}
      </td>
      <td className="px-3 py-2 text-gray-500">{fmtDate(hook.created_at)}</td>
      <td className="px-3 py-2 text-right space-x-1">
        {msg && <span className="text-[10px] text-gray-400 mr-2">{msg}</span>}
        <button type="button" disabled={busy} onClick={onTest}
          className="text-[11px] px-2 py-1 rounded border border-gray-700 hover:bg-gray-800 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-indigo-500">
          Test
        </button>
        <button type="button" onClick={onDeliveries}
          className="text-[11px] px-2 py-1 rounded border border-gray-700 hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-indigo-500">
          Deliveries
        </button>
        <button type="button" onClick={onEdit}
          className="text-[11px] px-2 py-1 rounded border border-gray-700 hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-indigo-500">
          Modifica
        </button>
        <button type="button" disabled={busy} onClick={onDelete}
          className="text-[11px] px-2 py-1 rounded border border-red-800 text-red-300 hover:bg-red-950/50 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-red-400">
          Elimina
        </button>
      </td>
    </tr>
  );
}

function WebhookFormDrawer({ hook, onClose, onSaved }) {
  const isEdit = Boolean(hook?.id);
  const [name, setName] = useState(hook?.name || '');
  const [url, setUrl] = useState(hook?.url || '');
  const [secret, setSecret] = useState('');
  const [events, setEvents] = useState(hook?.event_types || []);
  const [minPriority, setMinPriority] = useState(hook?.min_priority ?? 80);
  const [enabled, setEnabled] = useState(hook?.enabled ?? true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [createdSecret, setCreatedSecret] = useState(null);

  function toggleEvent(ev) {
    setEvents((cur) => (cur.includes(ev) ? cur.filter((e) => e !== ev) : [...cur, ev]));
  }

  async function onSubmit(e) {
    e.preventDefault();
    setErr('');
    if (!url.startsWith('http')) {
      setErr('URL deve iniziare con http(s)://');
      return;
    }
    setBusy(true);
    try {
      if (isEdit) {
        await updateWebhook(hook.id, {
          name, url,
          secret: secret || undefined,
          event_types: events,
          min_priority: Number(minPriority),
          enabled,
        });
        onSaved?.();
      } else {
        const res = await createWebhook({
          name, url,
          secret: secret || undefined,
          event_types: events,
          min_priority: Number(minPriority),
          enabled,
          created_by: 'ui',
        });
        // Show the secret ONCE — backend only returns it on create.
        setCreatedSecret(res?.secret || '(server-generated)');
      }
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || 'Errore');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div role="dialog" aria-modal="true" aria-label={isEdit ? 'Modifica webhook' : 'Nuovo webhook'}
      className="fixed inset-0 z-40 flex justify-end">
      <button type="button" aria-label="Chiudi" onClick={onClose}
        className="absolute inset-0 bg-black/50 cursor-default" />
      <div className="relative bg-gray-900 border-l border-gray-800 w-full max-w-md h-full overflow-y-auto p-5 space-y-4">
        <div className="flex items-start justify-between">
          <h2 className="text-sm font-semibold text-white">
            {isEdit ? 'Modifica webhook' : 'Nuovo webhook'}
          </h2>
          <button type="button" onClick={onClose} className="text-gray-500 hover:text-white text-lg leading-none px-2"
            aria-label="Chiudi pannello">×</button>
        </div>

        {createdSecret ? (
          <div className="space-y-3">
            <div className="bg-emerald-950/30 border border-emerald-800 rounded p-3 text-xs text-emerald-200">
              Webhook creato. <strong>Salva subito il secret</strong>: non sarà più mostrato in chiaro.
            </div>
            <code className="block bg-gray-950 border border-gray-700 rounded px-3 py-2 text-xs font-mono text-emerald-300 break-all">
              {createdSecret}
            </code>
            <button type="button" onClick={() => { setCreatedSecret(null); onSaved?.(); }}
              className="w-full bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-400">
              Ho salvato il secret
            </button>
          </div>
        ) : (
          <form onSubmit={onSubmit} className="space-y-3">
            <Field label="Nome" id="wh-name">
              <input id="wh-name" required value={name} onChange={(e) => setName(e.target.value)}
                className="w-full bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            </Field>
            <Field label="URL (https consigliato)" id="wh-url">
              <input id="wh-url" required type="url" value={url} onChange={(e) => setUrl(e.target.value)}
                placeholder="https://hooks.example.com/..." className="w-full bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            </Field>
            <Field label={isEdit ? 'Nuovo secret (lasciare vuoto per non cambiare)' : 'Secret (lascia vuoto per generare automaticamente)'} id="wh-secret">
              <input id="wh-secret" type="text" value={secret} onChange={(e) => setSecret(e.target.value)}
                className="w-full bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-sm text-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            </Field>
            <fieldset className="border border-gray-800 rounded p-2.5">
              <legend className="px-1 text-xs text-gray-400">Eventi</legend>
              <div className="space-y-1">
                {ALL_EVENTS.map((ev) => (
                  <label key={ev} className="flex items-center gap-2 text-xs text-gray-300">
                    <input type="checkbox" checked={events.includes(ev)} onChange={() => toggleEvent(ev)}
                      className="accent-indigo-500" />
                    <code className="font-mono">{ev}</code>
                  </label>
                ))}
              </div>
            </fieldset>
            <Field label="Min priority (0–100)" id="wh-min">
              <input id="wh-min" type="number" min="0" max="100" value={minPriority}
                onChange={(e) => setMinPriority(e.target.value)}
                className="w-full bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            </Field>
            <label className="flex items-center gap-2 text-xs text-gray-300">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)}
                className="accent-indigo-500" />
              Abilitato
            </label>

            {err && <p role="alert" className="text-xs text-red-400">{err}</p>}

            <button type="submit" disabled={busy || !name || !url}
              className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-800 disabled:text-gray-500 text-white text-sm font-semibold py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-400">
              {busy ? 'Salvataggio…' : isEdit ? 'Salva modifiche' : 'Crea webhook'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

function Field({ label, id, children }) {
  return (
    <div>
      <label htmlFor={id} className="block text-[11px] text-gray-400 mb-1">{label}</label>
      {children}
    </div>
  );
}

function DeliveriesDrawer({ hookId, onClose }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');

  useEffect(() => {
    let alive = true;
    listWebhookDeliveries(hookId, { limit: 50 })
      .then((p) => alive && setRows(p?.data || []))
      .catch((e) => alive && setErr(e?.response?.data?.detail || e?.message || 'Errore'))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [hookId]);

  return (
    <div role="dialog" aria-modal="true" aria-label="Storico delivery"
      className="fixed inset-0 z-40 flex justify-end">
      <button type="button" aria-label="Chiudi" onClick={onClose}
        className="absolute inset-0 bg-black/50 cursor-default" />
      <div className="relative bg-gray-900 border-l border-gray-800 w-full max-w-md h-full overflow-y-auto p-5 space-y-3">
        <div className="flex items-start justify-between">
          <h2 className="text-sm font-semibold text-white">Delivery — webhook #{hookId}</h2>
          <button type="button" onClick={onClose} className="text-gray-500 hover:text-white text-lg leading-none px-2"
            aria-label="Chiudi pannello">×</button>
        </div>
        {loading && <p className="text-xs text-gray-500">Caricamento…</p>}
        {err && <p role="alert" className="text-xs text-red-400">{err}</p>}
        {!loading && rows.length === 0 && (
          <p className="text-xs text-gray-600 italic">Nessuna consegna registrata.</p>
        )}
        <ul className="space-y-1.5 text-[11px]">
          {rows.map((r) => (
            <li key={r.id} className="border border-gray-800 rounded px-2 py-1.5 bg-gray-950/40">
              <div className="flex items-center justify-between gap-2">
                <span className="text-gray-300 truncate">{r.event_type}</span>
                <span className={
                  r.delivered_at
                    ? 'text-emerald-300 text-[10px]'
                    : 'text-amber-300 text-[10px]'
                }>
                  {r.delivered_at ? `OK ${r.response_status ?? ''}` : `pending · attempts ${r.attempts}`}
                </span>
              </div>
              <div className="text-gray-600 mt-0.5">
                {fmtDate(r.created_at)}
                {r.error_message && <span className="text-red-400 ml-2">{r.error_message}</span>}
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
