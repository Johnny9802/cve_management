'use client';

/**
 * Webhooks management page (Sprint 2 — S2.2).
 *
 * Closes FE-02 from the production-readiness review: backend exposes
 * /api/webhooks/* (CRUD + test + deliveries) but no UI surface
 * existed.
 */
import dynamicImport from 'next/dynamic';
import AppShell from '../../components/Shell/AppShell';

const WebhooksPage = dynamicImport(() => import('./WebhooksPage'), {
  ssr: false,
  loading: () => (
    <div className="text-xs text-gray-600 py-12 text-center">Caricamento…</div>
  ),
});

export const dynamic = 'force-dynamic';

export default function Page() {
  return (
    <AppShell
      title="Webhooks"
      subtitle="Endpoint esterni notificati su finding ad alta priorità · KEV · risk-acceptance"
    >
      <WebhooksPage />
    </AppShell>
  );
}
