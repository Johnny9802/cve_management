import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
});

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
