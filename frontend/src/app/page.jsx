'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import StatsBar from '../components/Dashboard/StatsBar';
import SeverityChart from '../components/Dashboard/SeverityChart';
import TimelineChart from '../components/Dashboard/TimelineChart';
import ProductsGrid from '../components/Products/ProductsGrid';
import AddProductModal from '../components/Products/AddProductModal';
import CVEFilters from '../components/CVE/CVEFilters';
import CVETable from '../components/CVE/CVETable';
import CVEDetailModal from '../components/CVE/CVEDetailModal';
import ExportButtons from '../components/CVE/ExportButtons';
import LiveSearchPanel from '../components/LiveSearch/LiveSearchPanel';
import SettingsPanel from '../components/Settings/SettingsPanel';
import RefreshButton from '../components/UI/RefreshButton';
import { getDashboard, getTimeline, getProducts, getCves, deleteProduct, syncProduct } from '../lib/api';

const TABS = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'live',      label: 'Live Search' },
  { key: 'settings',  label: 'Impostazioni' },
];

export default function Home() {
  const [tab, setTab] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [products, setProducts] = useState([]);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [cves, setCves] = useState({ data: [], total: 0, page: 1, pages: 1 });
  const [filters, setFilters] = useState({ page: 1, limit: 50, sort: 'priority_score', order: 'desc' });
  const [loadingCves, setLoadingCves] = useState(false);
  const [selectedCve, setSelectedCve] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast] = useState('');
  const toastTimer = useRef(null);

  function showToast(msg, ms = 3000) {
    setToast(msg);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(''), ms);
  }

  const loadDashboard = useCallback(async () => {
    setRefreshing(true);
    try {
      const [s, t, p] = await Promise.all([getDashboard(), getTimeline(), getProducts()]);
      setStats(s); setTimeline(t); setProducts(p);
      setLastRefreshed(new Date());
    } catch (err) {
      showToast(`Errore caricamento dashboard: ${err.message || 'unknown'}`);
    } finally {
      setRefreshing(false);
    }
  }, []);

  const loadCves = useCallback(async () => {
    setLoadingCves(true);
    try {
      const params = { ...filters };
      if (selectedProduct) params.product_id = selectedProduct;
      setCves(await getCves(params));
    } catch (err) {
      showToast(`Errore caricamento CVE: ${err.message || 'unknown'}`);
    }
    finally { setLoadingCves(false); }
  }, [filters, selectedProduct]);

  useEffect(() => { loadDashboard(); }, [loadDashboard]);
  useEffect(() => { if (tab === 'dashboard') loadCves(); }, [loadCves, tab]);
  useEffect(() => {
    const t = setInterval(loadDashboard, 30000);
    return () => clearInterval(t);
  }, [loadDashboard]);

  async function handleDeleteProduct(id) {
    const product = products.find((p) => p.id === id);
    const label = product ? `${product.name} ${product.version}` : `prodotto #${id}`;
    if (!confirm(`Eliminare "${label}" e i CVE associati?\nL'azione non è reversibile.`)) return;
    try {
      await deleteProduct(id);
      if (selectedProduct === id) setSelectedProduct(null);
      showToast(`✓ "${label}" eliminato`);
      loadDashboard();
    } catch (err) {
      showToast(`Errore eliminazione: ${err.message || 'unknown'}`);
    }
  }

  async function handleSyncProduct(id) {
    try {
      await syncProduct(id);
      showToast('Sync avviata, attendere il completamento…');
      setTimeout(loadDashboard, 2000);
    } catch (err) {
      showToast(`Errore sync: ${err.message || 'unknown'}`);
    }
  }

  function handleSelectProduct(id) {
    setSelectedProduct(id);
    setFilters((f) => ({ ...f, page: 1 }));
  }

  async function handleRefresh() {
    await Promise.all([loadDashboard(), tab === 'dashboard' ? loadCves() : Promise.resolve()]);
  }

  const selectedProductInfo = products.find((p) => p.id === selectedProduct);
  const lastRefreshedLabel = lastRefreshed
    ? `Ultimo aggiornamento: ${lastRefreshed.toLocaleTimeString('it-IT')}`
    : 'In attesa…';

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-screen-2xl mx-auto px-6 py-3 flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-base font-bold text-white">CVE Management</h1>
            <p className="text-xs text-gray-500">NVD · CISA KEV · EPSS</p>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <nav role="tablist" aria-label="Sezioni applicazione" className="flex bg-gray-800 rounded-lg p-0.5 gap-0.5 overflow-x-auto">
              {TABS.map(({ key, label }) => (
                <button
                  key={key}
                  role="tab"
                  aria-selected={tab === key}
                  onClick={() => setTab(key)}
                  className={`px-4 py-1.5 rounded-md text-xs font-medium transition whitespace-nowrap ${
                    tab === key ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>
            <span
              className="text-xs text-gray-500 hidden md:inline"
              aria-live="polite"
            >
              {refreshing ? 'Aggiornamento in corso…' : lastRefreshedLabel}
            </span>
            <RefreshButton onRefresh={handleRefresh} label="Aggiorna tutto" />
          </div>
        </div>
      </header>

      <main className="max-w-screen-2xl mx-auto px-6 py-6 space-y-6">
        <StatsBar stats={stats} />

        {/* ── DASHBOARD TAB ── */}
        {tab === 'dashboard' && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div className="lg:col-span-1 space-y-4">
              <ProductsGrid
                products={products}
                selectedId={selectedProduct}
                onSelect={handleSelectProduct}
                onDelete={handleDeleteProduct}
                onSync={handleSyncProduct}
                onAdd={() => setShowAddModal(true)}
              />
              <SeverityChart data={stats?.severity || []} />
            </div>

            <div className="lg:col-span-3 space-y-4">
              <TimelineChart data={timeline} />

              <div className="flex flex-col gap-3">
                {selectedProductInfo && (
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-gray-400">Filtrando per:</span>
                    <span className="bg-indigo-900/50 text-indigo-300 border border-indigo-700 px-2 py-0.5 rounded text-xs font-medium">
                      {selectedProductInfo.name} {selectedProductInfo.version}
                    </span>
                    <button
                      onClick={() => handleSelectProduct(null)}
                      aria-label="Rimuovi filtro prodotto"
                      className="text-xs text-gray-500 hover:text-white px-1.5 py-0.5 rounded border border-transparent hover:border-gray-700"
                    >
                      ✕ Rimuovi
                    </button>
                  </div>
                )}
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <CVEFilters filters={filters} onChange={setFilters} />
                  <ExportButtons
                    filters={filters}
                    stats={stats}
                    products={products}
                    selectedProductId={selectedProduct}
                  />
                </div>
              </div>

              <CVETable
                data={cves.data}
                total={cves.total}
                page={cves.page}
                pages={cves.pages}
                loading={loadingCves}
                onPageChange={(p) => setFilters((f) => ({ ...f, page: p }))}
                onRowClick={setSelectedCve}
                onAddProduct={() => setShowAddModal(true)}
              />
            </div>
          </div>
        )}

        {/* ── LIVE SEARCH TAB ── */}
        {tab === 'live' && <LiveSearchPanel onSelectCve={setSelectedCve} />}

        {/* ── SETTINGS TAB — mount only when active to avoid wasted hooks ── */}
        {tab === 'settings' && <SettingsPanel active />}
      </main>

      {/* Toasts */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-6 right-6 z-50 bg-gray-800 border border-gray-700 text-gray-100 text-sm px-4 py-2 rounded-lg shadow-xl max-w-sm"
        >
          {toast}
        </div>
      )}

      {showAddModal && (
        <AddProductModal
          onClose={() => setShowAddModal(false)}
          onAdded={() => {
            loadDashboard();
            setShowAddModal(false);
            showToast('✓ Prodotti importati');
          }}
        />
      )}
      {selectedCve && (
        <CVEDetailModal cveId={selectedCve} onClose={() => setSelectedCve(null)} />
      )}
    </div>
  );
}
