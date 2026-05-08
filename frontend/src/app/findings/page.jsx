'use client';

/**
 * Findings list page (Sprint 2 — S2.1).
 *
 * Closes FE-01 from the production-readiness review: the backend has
 * exposed /api/findings/* (list + status FSM + history + audit) since
 * Sprint 3-backend, but no UI surface existed. Triage-pipeline cards
 * could only flip a status one card at a time, with no central place
 * to triage the backlog.
 *
 * Layout:
 *   - tab strip per status (open / in_review / planned / accepted_risk /
 *     remediated / closed / false_positive / all)
 *   - data table sorted by priority desc
 *   - row click opens a drawer with history + status picker
 *
 * URL state lives in `?status=...&page=...` so deep-links work
 * (sharing "all open findings" is just sharing the URL).
 */
import dynamicImport from 'next/dynamic';
import AppShell from '../../components/Shell/AppShell';

// Drawer is a client component with state; use next/dynamic to keep
// the initial bundle small and the SSR-fallback simple.
const FindingsPage = dynamicImport(() => import('./FindingsPage'), {
  ssr: false,
  loading: () => (
    <div className="text-xs text-gray-600 py-12 text-center">Caricamento…</div>
  ),
});

export const dynamic = 'force-dynamic';

export default function Page() {
  return (
    <AppShell
      title="Findings"
      subtitle="Triage centralizzato dei finding con stato corrente e storico"
    >
      <FindingsPage />
    </AppShell>
  );
}
