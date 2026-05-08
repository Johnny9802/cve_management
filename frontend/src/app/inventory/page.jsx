'use client';

/**
 * Inventory page (Sprint 2 — S2.4).
 *
 * Closes FE-11. Until now CSV upload only existed inside the legacy
 * AddProductModal (visible from the legacy `/`). This page makes the
 * inventory a first-class workflow surface with a prominent drop-zone
 * when the inventory is empty and a structured product list otherwise.
 *
 * The ``?type=software|os`` filter is reserved for a future split — the
 * backend doesn't carry the field yet, so for now the tabs only filter
 * client-side on a heuristic ("operating-system"-ish vendor names). The
 * UI hook is here so the day the backend gains the column we don't have
 * to redesign the page.
 */
import dynamicImport from 'next/dynamic';
import AppShell from '../../components/Shell/AppShell';

const InventoryPage = dynamicImport(() => import('./InventoryPage'), {
  ssr: false,
  loading: () => (
    <div className="text-xs text-gray-600 py-12 text-center">Caricamento…</div>
  ),
});

export const dynamic = 'force-dynamic';

export default function Page() {
  return (
    <AppShell
      title="Inventario"
      subtitle="Software & OS sotto monitoraggio · upload CSV · sync manuale"
    >
      <InventoryPage />
    </AppShell>
  );
}
