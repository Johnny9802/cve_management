'use strict';

const axios = require('axios');
const { parseNvdCve } = require('./nvd.service');
const { retry } = require('../utils/retry');

const BASE = 'https://cve.circl.lu/api';
const client = axios.create({ baseURL: BASE, timeout: 20000 });
const MAX_PAGES = 50; // safety cap: 50 × pageSize(10) = 500 CVEs max

const withRetry = (fn) => retry(fn, { attempts: 3, baseDelayMs: 1000 });

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Fetch a single page from CIRCL and normalise the response.
async function fetchPage(vendor, product, page) {
  const resp = await withRetry(() =>
    client.get(`/search/${encodeURIComponent(vendor)}/${encodeURIComponent(product)}`, {
      params: { page },
    })
  );

  const data = resp.data;
  // fkie_nvd can be an array of [cve_id, nvd_obj] pairs OR an object {cve_id: nvd_obj}.
  // Handle both to be safe.
  const raw = data.results?.fkie_nvd || [];
  let entries;
  if (Array.isArray(raw)) {
    entries = raw; // already [[id, obj], …]
  } else if (typeof raw === 'object') {
    entries = Object.entries(raw);
  } else {
    entries = [];
  }

  const cves = entries
    .map(([, nvdData]) => parseNvdCve(nvdData))
    .filter(Boolean);

  return {
    cves,
    total: data.total_count || 0,
    page: data.page || page,
    pageSize: data.page_size || 10,
  };
}

/**
 * Fetch ALL pages for vendor/product and return the full CVE list.
 * Caches the full set under `circl:all:{vendor}:{product}` (1 h fresh / 24 h stale).
 * Subsequent calls are served from cache instantly.
 */
async function fetchAllCves(vendor, product) {
  const first = await fetchPage(vendor, product, 1);
  const allCves = [...first.cves];
  const totalPages = Math.min(
    Math.ceil((first.total || first.cves.length) / (first.pageSize || 10)),
    MAX_PAGES
  );

  for (let p = 2; p <= totalPages; p++) {
    await sleep(400); // be polite to CIRCL
    try {
      const page = await fetchPage(vendor, product, p);
      allCves.push(...page.cves);
    } catch (err) {
      console.warn(`CIRCL page ${p} failed (${err.message}), stopping early with ${allCves.length} CVEs`);
      break;
    }
  }

  return { cves: allCves, total: first.total || allCves.length, pageSize: first.pageSize || 10 };
}

// Public search: returns only the requested page after in-memory filtering.
// severity, year are applied here so callers get accurate filtered counts.
async function searchByVendorProduct(vendor, product, { page = 1 } = {}) {
  return { cves: (await fetchAllCves(vendor, product)).cves, total: 0, page, pageSize: 10, source: 'CIRCL' };
}

async function browseProducts(vendor) {
  const resp = await withRetry(() =>
    client.get(`/browse/${encodeURIComponent(vendor)}`)
  );
  return Array.isArray(resp.data) ? resp.data : [];
}

async function listVendors() {
  const resp = await withRetry(() => client.get('/browse'));
  return Array.isArray(resp.data) ? resp.data : [];
}

async function getCveById(cveId) {
  try {
    const resp = await withRetry(() => client.get(`/cve/${cveId}`));
    const d = resp.data;
    if (!d || !d.cveMetadata) return null;

    const cna = d.containers?.cna || {};
    const adp = (d.containers?.adp || []).find((a) =>
      a.providerMetadata?.orgId?.includes('nvd')
    );
    const desc = (cna.descriptions || []).find((x) => x.lang === 'en')?.value || '';
    const metrics = [...(cna.metrics || []), ...(adp?.metrics || [])];

    let cvssV3 = null, cvssV2 = null;
    for (const m of metrics) {
      if (m.cvssV3_1 && !cvssV3) cvssV3 = m.cvssV3_1;
      if (m.cvssV3_0 && !cvssV3) cvssV3 = m.cvssV3_0;
      if (m.cvssV2_0 && !cvssV2) cvssV2 = m.cvssV2_0;
    }

    return {
      cve_id: d.cveMetadata.cveId,
      description: desc,
      published_at: d.cveMetadata.datePublished,
      last_modified_at: d.cveMetadata.dateUpdated,
      cvss_v3_score: cvssV3?.baseScore ?? null,
      cvss_v3_vector: cvssV3?.vectorString ?? null,
      cvss_v2_score: cvssV2?.baseScore ?? null,
      severity: cvssV3?.baseSeverity?.toUpperCase() || 'NONE',
      references: (cna.references || []).map((r) => ({ url: r.url, tags: r.tags || [] })),
      weaknesses: (cna.problemTypes || []).flatMap(
        (p) => p.descriptions?.map((x) => x.cweId || x.description) || []
      ),
      affected_cpe: [],
      source: 'CIRCL',
    };
  } catch {
    return null;
  }
}

async function ping() {
  const start = Date.now();
  await axios.get(`${BASE}/last`, { timeout: 8000, params: { limit: 1 } });
  return Date.now() - start;
}

module.exports = { fetchAllCves, searchByVendorProduct, browseProducts, listVendors, getCveById, ping };
