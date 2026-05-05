'use client';

/**
 * Dashboards hub at /dashboards — entry point with 4 large cards.
 *
 * Each card describes a persona, what question it answers, and what
 * the user can do there. A "Imposta come default" star toggles
 * localStorage; if a default is set, the hub displays a banner with a
 * "Apri default" shortcut.
 */
import { useEffect, useState } from 'react';
import Link from 'next/link';
import AppShell from '../../components/Shell/AppShell';
import { VALID_KEYS, getDefaultDashboard, setDefaultDashboard } from '../../lib/dashboard-prefs';

const DASHBOARDS = [
  {
    key: 'triage',
    badge: 'B',
    title: 'SOC Triage',
    href: '/dashboards/triage',
    persona: 'SOC analyst · vulnerability analyst',
    question: 'Cosa devo patchare oggi?',
    body: [
      'Top urgenze sull\'intero catalogo + tre canali specializzati: nuova exploitability, KEV in invecchiamento, EPSS hotlist (alta probabilità ma non KEV).',
      'Filtri rapidi (KEV / PoC / Nuclei / EPSS / Priority) con stato in URL.',
    ],
    accent: 'border-red-700/60 bg-red-950/20 hover:border-red-600',
    badgeCls: 'bg-red-900/40 text-red-200 border-red-800',
  },
  {
    key: 'remediation',
    badge: 'D',
    title: 'Remediation & Governance',
    href: '/dashboards/remediation',
    persona: 'Vulnerability manager · governance · audit',
    question: 'Sono chiusi in tempo? Chi possiede?',
    body: [
      'Pipeline finding (FSM kanban) con cambio stato, matrice SLA × severità, MTTR per severità.',
      'Lifecycle accettazioni rischio + audit log con diff mascherato.',
      'Export CSV per SLA breached e audit log.',
    ],
    accent: 'border-indigo-700/60 bg-indigo-950/20 hover:border-indigo-600',
    badgeCls: 'bg-indigo-900/40 text-indigo-200 border-indigo-800',
  },
  {
    key: 'exposure',
    badge: 'C',
    title: 'Asset & Product Exposure',
    href: '/dashboards/exposure',
    persona: 'IT ops · asset owner · product owner',
    question: 'Quali prodotti / vendor mi stanno facendo male?',
    body: [
      'Top vendor pesati su priority, heatmap prodotto × severità, top per KEV / Critical.',
      'Coperture inventario (CPE risolti, sync stale).',
      'Candidati EOL / legacy: prodotti critical con CVE non più aggiornate.',
    ],
    accent: 'border-amber-700/60 bg-amber-950/20 hover:border-amber-600',
    badgeCls: 'bg-amber-900/40 text-amber-200 border-amber-800',
  },
  {
    key: 'executive',
    badge: 'A',
    title: 'Executive Risk Overview',
    href: '/dashboards/executive',
    persona: 'CISO · management · board',
    question: 'Stiamo migliorando? Cosa dico al board?',
    body: [
      'Risk score composito 0-100 e KPI trend (KEV, finding, breach) con sparkline.',
      'Aging buckets, velocity remediation 12 settimane, top owners 90 giorni.',
      'Export PDF in un click.',
    ],
    accent: 'border-emerald-700/60 bg-emerald-950/20 hover:border-emerald-600',
    badgeCls: 'bg-emerald-900/40 text-emerald-200 border-emerald-800',
  },
];

export default function DashboardsHub() {
  const [defaultKey, setDefaultKey] = useState(null);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setDefaultKey(getDefaultDashboard());
    setHydrated(true);
  }, []);

  function pickDefault(key) {
    const next = defaultKey === key ? null : key;
    setDefaultDashboard(next);
    setDefaultKey(next);
  }

  const defaultDashboard = DASHBOARDS.find((d) => d.key === defaultKey);

  return (
    <AppShell
      title="Dashboards SecOps"
      subtitle="4 dashboard, 4 personae, 4 domande operative diverse"
    >
      {hydrated && defaultDashboard && (
        <div className="bg-indigo-950/30 border border-indigo-800 rounded-xl p-3 flex items-center justify-between gap-3 flex-wrap">
          <div className="text-sm text-indigo-200">
            La tua dashboard di default è{' '}
            <strong className="text-white">{defaultDashboard.title}</strong>.
          </div>
          <div className="flex gap-2">
            <Link
              href={defaultDashboard.href}
              className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-lg transition focus:outline-none"
            >
              Apri default →
            </Link>
            <button
              type="button"
              onClick={() => pickDefault(defaultKey)}
              className="text-xs text-indigo-300 hover:text-white px-3 py-1.5 border border-indigo-800 hover:border-indigo-700 rounded-lg focus:outline-none"
            >
              Rimuovi default
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {DASHBOARDS.map((d) => {
          const isDefault = defaultKey === d.key;
          return (
            <article
              key={d.key}
              className={`relative rounded-xl border p-5 transition ${d.accent}`}
            >
              <header className="flex items-start gap-3">
                <span className={`text-xs font-mono px-2 py-1 rounded border ${d.badgeCls}`}>
                  {d.badge}
                </span>
                <div className="flex-1 min-w-0">
                  <h2 className="text-base font-semibold text-white">{d.title}</h2>
                  <p className="text-xs text-gray-400">{d.persona}</p>
                </div>
                <button
                  type="button"
                  onClick={() => pickDefault(d.key)}
                  aria-label={isDefault ? 'Rimuovi come default' : 'Imposta come default'}
                  aria-pressed={isDefault}
                  title={isDefault ? 'Rimuovi come default' : 'Imposta come default'}
                  className={`text-base px-2 py-1 rounded transition focus:outline-none ${
                    isDefault
                      ? 'text-amber-300 hover:text-amber-200'
                      : 'text-gray-600 hover:text-gray-300'
                  }`}
                >
                  {isDefault ? '★' : '☆'}
                </button>
              </header>

              <blockquote className="mt-3 text-sm text-gray-200 italic border-l-2 border-gray-700 pl-3">
                {d.question}
              </blockquote>

              <ul className="mt-3 space-y-1.5 text-xs text-gray-400">
                {d.body.map((line, i) => (
                  <li key={i} className="flex gap-2">
                    <span aria-hidden className="text-gray-600">·</span>
                    <span>{line}</span>
                  </li>
                ))}
              </ul>

              <footer className="mt-4 flex items-center gap-2">
                <Link
                  href={d.href}
                  className="text-sm bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-lg transition focus:outline-none"
                >
                  Apri →
                </Link>
                {isDefault && (
                  <span className="text-[11px] text-amber-300">★ default</span>
                )}
              </footer>
            </article>
          );
        })}
      </div>

      <p className="text-xs text-gray-500 text-center pt-2">
        Suggerimento: scegli ★ una dashboard come default e usa &laquo;Apri default&raquo; come scorciatoia
        di lavoro. La preferenza è salvata localmente nel browser.
      </p>
    </AppShell>
  );
}
