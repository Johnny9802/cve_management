'use client';

/**
 * Dashboard C — Asset & Product Exposure (Sprint Dashboards 3).
 *
 * Layout: coverage strip on top (data-quality), then top-vendors bar
 * full width, then heat-map + side panels (KEV / critical / EOL),
 * Drill-down: click a vendor / product → routes to /dashboards/triage
 * with the vendor pre-filtered (Sprint 4 will wire the param).
 */
import { useCallback, useEffect, useState } from 'react';
import AppShell from '../../../components/Shell/AppShell';
import InventoryCoverageStrip from '../../../components/Exposure/InventoryCoverageStrip';
import TopVendorsBar from '../../../components/Exposure/TopVendorsBar';
import ProductHeatmap from '../../../components/Exposure/ProductHeatmap';
import TopProductsTable from '../../../components/Exposure/TopProductsTable';
import EolFlagPanel from '../../../components/Exposure/EolFlagPanel';
import { getDashboardExposure } from '../../../lib/api';

export default function ExposurePage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastRefreshed, setLastRefreshed] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const payload = await getDashboardExposure({ top_limit: 10 });
      setData(payload);
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Errore caricamento');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <AppShell
      title="Asset & Product Exposure"
      subtitle="Quale corner dell'inventario sta facendo trapelare il rischio"
      onRefresh={load}
      lastRefreshed={lastRefreshed}
    >
      {error && (
        <div
          className="bg-red-950/30 border border-red-800 rounded-xl p-3 text-sm text-red-300"
          role="alert"
        >
          {error}
        </div>
      )}

      <InventoryCoverageStrip
        coverage={data?.inventory_coverage}
        loading={loading && !data}
      />

      <TopVendorsBar
        vendors={data?.top_vendors || []}
        loading={loading && !data}
      />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2">
          <ProductHeatmap
            heatmap={data?.heatmap || []}
            loading={loading && !data}
          />
        </div>
        <div className="space-y-4">
          <TopProductsTable
            title="Top KEV per prodotto"
            hint="Prodotti con il maggior numero di CVE in CISA KEV"
            rows={data?.top_products_by_kev || []}
            loading={loading && !data}
            emptyText="Nessun prodotto con CVE in KEV."
          />
          <TopProductsTable
            title="Top Critical per prodotto"
            hint="Prodotti con il maggior numero di CVE critical"
            rows={data?.top_products_by_critical || []}
            loading={loading && !data}
            emptyText="Nessun prodotto con CVE critical."
          />
        </div>
      </div>

      <EolFlagPanel
        items={data?.eol_candidates || []}
        loading={loading && !data}
      />
    </AppShell>
  );
}
