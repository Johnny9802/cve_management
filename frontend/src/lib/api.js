import axios from 'axios';
import { clearSession, getAccessToken, getRefreshToken, setSession } from './auth';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
});

// ── Auth interceptors (Sprint 1 — S1-FE) ─────────────────────────────────
//
// Request: attach the bearer token if present. Requests with
//   `meta: { skipAuth: true }` (login, refresh) skip this.
// Response: on 401, try one silent refresh; if that fails, clear the
//   session and bounce to /login. The refresh attempt is guarded by an
//   in-flight promise so concurrent 401s collapse into one refresh call.

let inFlightRefresh = null;

api.interceptors.request.use((config) => {
  if (config.meta?.skipAuth) return config;
  const token = getAccessToken();
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

async function refreshTokens() {
  const refresh_token = getRefreshToken();
  if (!refresh_token) throw new Error('no refresh token');
  const { data } = await axios.post(
    '/api/auth/refresh',
    { refresh_token },
    { timeout: 10000 },
  );
  setSession(data);
  return data.access_token;
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error?.response?.status;
    const config = error?.config;
    if (status !== 401 || !config || config._retried) {
      return Promise.reject(error);
    }
    // Don't try to refresh if THIS request was already an auth request.
    const url = config.url || '';
    if (url.includes('/auth/login') || url.includes('/auth/refresh')) {
      return Promise.reject(error);
    }

    config._retried = true;
    try {
      inFlightRefresh = inFlightRefresh ?? refreshTokens();
      const newAccess = await inFlightRefresh;
      inFlightRefresh = null;
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${newAccess}`;
      return api.request(config);
    } catch (refreshErr) {
      inFlightRefresh = null;
      clearSession();
      if (typeof window !== 'undefined') {
        const next = window.location.pathname + window.location.search;
        window.location.href = `/login?next=${encodeURIComponent(next)}`;
      }
      return Promise.reject(refreshErr);
    }
  },
);

// ── Auth endpoints ───────────────────────────────────────────────────────
export const login = (email, password) =>
  axios
    .post('/api/auth/login', { email, password }, { timeout: 10000 })
    .then((r) => r.data);

export const fetchMe = () => api.get('/auth/me').then((r) => r.data);

export const logout = () => {
  clearSession();
  if (typeof window !== 'undefined') window.location.href = '/login';
};

export const getDashboard = () => api.get('/dashboard').then((r) => r.data);
export const getTimeline = () => api.get('/dashboard/timeline').then((r) => r.data);

export const getProducts = () => api.get('/products').then((r) => r.data);
export const addProduct = (data) => api.post('/products', data).then((r) => r.data);
export const addProductsBulk = (products) => api.post('/products/bulk', { products }).then((r) => r.data);
export const deleteProduct = (id) => api.delete(`/products/${id}`).then((r) => r.data);
export const syncProduct = (id) => api.post(`/products/${id}/sync`).then((r) => r.data);

export const getCves = (params) => api.get('/cves', { params }).then((r) => r.data);
export const getCveDetail = (id) => api.get(`/cves/${id}`).then((r) => r.data);
export const exportCvesCsv = (params) => {
  const qs = new URLSearchParams(params).toString();
  return `/api/cves/export?${qs}`;
};

// P3 / P6 — Live exploitability intel
export const getCveIntel = (id, { refresh = false } = {}) =>
  api
    .get(`/cves/${id}/intel`, { params: refresh ? { refresh: 'true' } : {} })
    .then((r) => r.data);

// Sprint Dashboards 1 — SOC Triage aggregator
export const getDashboardTriage = (params = {}) =>
  api.get('/dashboard/triage', { params }).then((r) => r.data);

// Sprint Dashboards 2 — Remediation & Governance
export const getDashboardRemediation = (params = {}) =>
  api.get('/dashboard/remediation', { params }).then((r) => r.data);
export const getOwnerWorkload = () =>
  api.get('/dashboard/owner-workload').then((r) => r.data);
export const getRiskAcceptanceSummary = (params = {}) =>
  api.get('/risk-acceptances/summary', { params }).then((r) => r.data);
export const getSlaSummary = () =>
  api.get('/findings/sla/summary').then((r) => r.data);
export const getMttr = (params = { period: '90d' }) =>
  api.get('/findings/mttr', { params }).then((r) => r.data);
export const getAuditLog = (params = {}) =>
  api.get('/audit-log', { params }).then((r) => r.data);
export const getSlaList = (params = {}) =>
  api.get('/findings/sla', { params }).then((r) => r.data);

// Sprint Dashboards 3 — Asset Exposure (C) + Executive (A)
export const getDashboardExposure = (params = {}) =>
  api.get('/dashboard/exposure', { params }).then((r) => r.data);
export const getDashboardExec = (params = {}) =>
  api.get('/dashboard/exec', { params }).then((r) => r.data);

// P7 — Webhooks management
export const listWebhooks = () => api.get('/webhooks').then((r) => r.data);
export const createWebhook = (data) => api.post('/webhooks', data).then((r) => r.data);
export const updateWebhook = (id, data) => api.patch(`/webhooks/${id}`, data).then((r) => r.data);
export const deleteWebhook = (id) => api.delete(`/webhooks/${id}`).then((r) => r.data);
export const testWebhook = (id) => api.post(`/webhooks/${id}/test`).then((r) => r.data);
export const listWebhookDeliveries = (id, params = {}) =>
  api.get(`/webhooks/${id}/deliveries`, { params }).then((r) => r.data);

export const getSystemStatus = (service) =>
  api.get('/system/status', { params: service ? { service } : {} }).then((r) => r.data);
export const getSystemConfig = () => api.get('/system/config').then((r) => r.data);
export const updateSystemConfig = (key, value) =>
  api.patch('/system/config', { key, value }).then((r) => r.data);

export const getFindingStats = () => api.get('/findings/stats').then((r) => r.data);
export const getOpenFindings = (params) => api.get('/findings', { params }).then((r) => r.data);
export const updateFinding = (productId, cveId, data) =>
  api.patch(`/findings/${productId}/${cveId}`, data).then((r) => r.data);
export const getFindingHistory = (productId, cveId) =>
  api.get(`/findings/${productId}/${cveId}/history`).then((r) => r.data);
