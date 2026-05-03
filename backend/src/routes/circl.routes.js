'use strict';

const express = require('express');
const router = express.Router();
const circl = require('../services/circl.service');
const { fetchEpssScores } = require('../services/epss.service');
const { enrichWithKev } = require('../services/cisa-kev.service');
const { computePriorityScore } = require('../services/priority.service');
const cache = require('../services/cache.service');

// ── In-memory helpers ─────────────────────────────────────────────────────────

function applyFilters(cves, { severity, year, kev } = {}) {
  return cves.filter((c) => {
    if (severity && c.severity !== severity.toUpperCase()) return false;
    if (year && c.published_at) {
      if (new Date(c.published_at).getFullYear() !== parseInt(year)) return false;
    }
    if (kev === 'true' && !c.in_cisa_kev) return false;
    return true;
  });
}

function paginate(items, page, limit) {
  const p = Math.max(1, page);
  const l = Math.min(100, Math.max(1, limit));
  return {
    data:  items.slice((p - 1) * l, p * l),
    total: items.length,
    page:  p,
    limit: l,
    pages: Math.ceil(items.length / l),
  };
}

// Enrich a list of parsed CVEs with EPSS + KEV + priority_score.
async function enrich(cves) {
  if (!cves.length) return [];
  const ids = cves.map((c) => c.cve_id);
  const [epssData, kevData] = await Promise.all([
    fetchEpssScores(ids),
    enrichWithKev(ids),
  ]);
  return cves.map((cve) => {
    const epss = epssData[cve.cve_id] || { score: 0, percentile: 0 };
    const kev  = kevData[cve.cve_id]  || { inKev: false };
    return {
      ...cve,
      epss_score:      epss.score,
      epss_percentile: epss.percentile,
      in_cisa_kev:     kev.inKev,
      priority_score: computePriorityScore({
        cvssScore:   cve.cvss_v3_score,
        severity:    cve.severity,
        epssScore:   epss.score,
        inKev:       kev.inKev,
        publishedAt: cve.published_at,
      }),
      source: 'CIRCL',
    };
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * GET /api/circl?vendor=X&product=Y&page=1&limit=20&severity=HIGH&year=2023&kev=true
 *
 * Strategy:
 * 1. Fetch ALL pages from CIRCL once and cache the full enriched list (1 h TTL).
 * 2. Apply severity/year/kev filters in memory — works on any page.
 * 3. Paginate in memory — page 2, 3, … always work.
 */
router.get('/', async (req, res) => {
  const {
    vendor, product,
    page = 1, limit = 20,
    severity, year, kev,
  } = req.query;

  if (!vendor || !product) {
    return res.status(400).json({ error: 'vendor e product sono obbligatori' });
  }

  const allKey    = `circl:all:${vendor}:${product}`;
  const pageNum   = Math.max(1, parseInt(page));
  const limitNum  = Math.min(100, Math.max(1, parseInt(limit)));

  try {
    // ── 1. Load full enriched set (cache-first) ──────────────────────────────
    let allEnriched = await cache.get(allKey);

    if (!allEnriched) {
      // Not cached — fetch all CIRCL pages (may take a few seconds first time)
      const { cves: rawCves, total } = await circl.fetchAllCves(vendor, product);
      allEnriched = await enrich(rawCves);

      if (allEnriched.length) {
        // 1 h fresh, 24 h stale
        await cache.setWithStale(allKey, allEnriched, 3600);
      }
    }

    // ── 2. Filter in memory ──────────────────────────────────────────────────
    const filtered = applyFilters(allEnriched, { severity, year, kev });

    // Sort by priority_score desc (consistent with dashboard)
    filtered.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));

    // ── 3. Paginate ──────────────────────────────────────────────────────────
    const result = paginate(filtered, pageNum, limitNum);

    res.json({
      ...result,
      total_raw: allEnriched.length,
      source:    'CIRCL',
      cached:    !!(await cache.get(allKey)), // true when served from cache
    });
  } catch (err) {
    const httpStatus = err.response?.status;
    console.error('CIRCL error:', { vendor, product, status: httpStatus, message: err.message });

    // Try stale fallback before giving up
    const stale = await cache.getStale(allKey);
    if (stale) {
      const filtered = applyFilters(stale, { severity, year, kev });
      filtered.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));
      const result = paginate(filtered, pageNum, limitNum);
      res.set('X-Data-Source', 'stale-cache');
      return res.json({ ...result, total_raw: stale.length, source: 'CIRCL', stale: true });
    }

    if (httpStatus >= 400 && httpStatus < 500) {
      return res.status(httpStatus).json({ error: `CIRCL: ${err.message}` });
    }
    res.status(503).json({
      error: 'CIRCL_UNAVAILABLE',
      detail: httpStatus ? `HTTP ${httpStatus}` : err.message,
      data: [], total: 0, pages: 0,
    });
  }
});

// GET /api/circl/products?vendor=X — autocomplete
router.get('/products', async (req, res) => {
  const { vendor } = req.query;
  if (!vendor) return res.status(400).json({ error: 'vendor è obbligatorio' });

  const cacheKey = `circl:products:${vendor}`;
  const cached = await cache.get(cacheKey);
  if (cached) return res.json(cached);

  try {
    const products = await circl.browseProducts(vendor);
    await cache.setWithStale(cacheKey, products, 3600);
    res.json(products);
  } catch (err) {
    const stale = await cache.getStale(cacheKey);
    if (stale) { res.set('X-Data-Source', 'stale-cache'); return res.json(stale); }
    const s = err.response?.status;
    if (s >= 400 && s < 500) return res.status(s).json({ error: err.message });
    res.status(503).json({ error: 'CIRCL_UNAVAILABLE', data: [] });
  }
});

module.exports = router;
