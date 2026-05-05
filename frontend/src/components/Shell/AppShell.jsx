'use client';

/**
 * Shared layout for the new dashboard routes.
 *
 * Renders a sticky topbar with the brand + tabs back to legacy + a
 * RefreshButton, a left sidebar (Sidebar.jsx) and the page content.
 * The legacy `/` page is unchanged; Dashboard B and future siblings
 * mount under `<AppShell>` so they all share chrome and a11y posture.
 */
import { useState } from 'react';
import Link from 'next/link';
import Sidebar from './Sidebar';
import DashboardSwitcher from './DashboardSwitcher';
import RefreshButton from '../UI/RefreshButton';

export default function AppShell({ title, subtitle, actions, onRefresh, lastRefreshed, children }) {
  const [refreshKey, setRefreshKey] = useState(0);

  async function handleRefresh() {
    if (!onRefresh) {
      setRefreshKey((k) => k + 1);
      return;
    }
    await onRefresh();
    setRefreshKey((k) => k + 1);
  }

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Topbar */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-30 min-h-[3.5rem]">
        <div className="max-w-screen-2xl mx-auto px-4 lg:px-6 py-2 flex items-center justify-between gap-3 flex-wrap">
          <Link href="/dashboards" className="flex flex-col leading-tight shrink-0">
            <span className="text-base font-bold text-white">CVE Management</span>
            <span className="text-xs text-gray-500 hidden sm:block">NVD · KEV · EPSS · vulnx</span>
          </Link>
          <DashboardSwitcher />
          <div className="flex items-center gap-3 flex-wrap ml-auto">
            <span className="text-xs text-gray-500 hidden md:inline" aria-live="polite">
              {lastRefreshed
                ? `Ultimo aggiornamento: ${new Date(lastRefreshed).toLocaleTimeString('it-IT')}`
                : '—'}
            </span>
            <RefreshButton onRefresh={handleRefresh} label="Aggiorna" />
          </div>
        </div>
      </header>

      <div className="max-w-screen-2xl mx-auto flex">
        <Sidebar />

        <main className="flex-1 min-w-0 px-4 lg:px-6 py-6 space-y-6">
          {(title || actions) && (
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                {title && <h1 className="text-lg font-bold text-white">{title}</h1>}
                {subtitle && <p className="text-sm text-gray-400 mt-0.5">{subtitle}</p>}
              </div>
              {actions && <div className="flex items-center gap-2">{actions}</div>}
            </div>
          )}
          <div data-refresh-key={refreshKey}>{children}</div>
        </main>
      </div>
    </div>
  );
}
