'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { getSystemStatus, getSystemConfig } from '../../lib/api';
import ApiStatusGrid from './ApiStatusGrid';
import ConfigTable from './ConfigTable';

const POLL_INTERVAL_MS = 60_000;

export default function SettingsPanel({ active }) {
  const [statuses, setStatuses]           = useState(null);
  const [configs, setConfigs]             = useState(null);
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [loadingConfig, setLoadingConfig] = useState(false);
  const [errorStatus, setErrorStatus]     = useState('');
  const [errorConfig, setErrorConfig]     = useState('');
  const [lastChecked, setLastChecked]     = useState(null);
  const [pollFailed, setPollFailed]       = useState(false);
  const intervalRef = useRef(null);

  const fetchStatus = useCallback(async (silent = false) => {
    if (!silent) setLoadingStatus(true);
    setErrorStatus('');
    try {
      const data = await getSystemStatus();
      setStatuses(data);
      setLastChecked(new Date());
      setPollFailed(false);
    } catch (err) {
      const status = err?.response?.status;
      if (!silent) {
        setErrorStatus(
          status === 404
            ? 'Endpoint /api/system/status non trovato — riavvia il backend.'
            : 'Impossibile contattare il backend. Controlla che sia in esecuzione.'
        );
      } else {
        setPollFailed(true);
      }
    } finally {
      if (!silent) setLoadingStatus(false);
    }
  }, []);

  const fetchConfig = useCallback(async () => {
    setLoadingConfig(true);
    setErrorConfig('');
    try {
      const { items } = await getSystemConfig();
      setConfigs(items);
    } catch (err) {
      const status = err?.response?.status;
      if (status === 404) {
        setErrorConfig('Endpoint /api/system/config non trovato — riavvia il backend per applicare le ultime modifiche.');
      } else {
        setErrorConfig('Impossibile caricare la configurazione. Controlla che il backend sia in esecuzione.');
      }
    } finally {
      setLoadingConfig(false);
    }
  }, []);

  const testOne = useCallback(async (serviceId) => {
    try {
      const data = await getSystemStatus(serviceId);
      setStatuses((prev) => ({ ...prev, ...data }));
    } catch { /* individual test failure shown on the card */ }
  }, []);

  useEffect(() => {
    if (!active) {
      clearInterval(intervalRef.current);
      return;
    }
    fetchStatus();
    fetchConfig();
    intervalRef.current = setInterval(() => fetchStatus(true), POLL_INTERVAL_MS);
    return () => clearInterval(intervalRef.current);
  }, [active, fetchStatus, fetchConfig]);

  if (!active) return null;

  return (
    <div className="space-y-8">

      {/* ── API Status ── */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-semibold text-gray-100">Stato API</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              {lastChecked
                ? <>Aggiornato {lastChecked.toLocaleTimeString('it-IT')} {pollFailed && <span className="text-amber-400 ml-1">● errore ultimo poll</span>}</>
                : 'Verifica in corso…'}
            </p>
          </div>
          <button
            onClick={() => fetchStatus()}
            disabled={loadingStatus}
            className="text-xs border border-gray-700 text-gray-400 hover:text-white px-3 py-1.5 rounded-lg transition disabled:opacity-40"
          >
            {loadingStatus ? <span className="animate-spin inline-block">⟳</span> : '↻ Aggiorna tutto'}
          </button>
        </div>

        {errorStatus ? (
          <div className="bg-red-950/30 border border-red-800 rounded-xl p-4 flex items-center justify-between">
            <span className="text-sm text-red-300">{errorStatus}</span>
            <button onClick={() => fetchStatus()} className="text-xs text-red-400 hover:text-red-200 underline ml-4">Riprova</button>
          </div>
        ) : (
          <ApiStatusGrid statuses={statuses} onTest={testOne} loading={loadingStatus} />
        )}
      </section>

      {/* ── API Configuration ── */}
      <section>
        <div className="mb-4">
          <h2 className="text-base font-semibold text-gray-100">Configurazione API</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Le chiavi inserite qui sovrascrivono le variabili d&apos;ambiente senza riavvio.
            I valori sono cifrati in transito, ma salvati in chiaro nel database.
          </p>
        </div>

        {errorConfig ? (
          <div className="bg-red-950/30 border border-red-800 rounded-xl p-4 flex items-center justify-between">
            <span className="text-sm text-red-300">{errorConfig}</span>
            <button onClick={fetchConfig} className="text-xs text-red-400 hover:text-red-200 underline ml-4">Riprova</button>
          </div>
        ) : (
          <ConfigTable
            configs={configs}
            loading={loadingConfig}
            onRefreshStatus={() => fetchStatus(true)}
          />
        )}
      </section>

    </div>
  );
}
