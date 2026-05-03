const express = require('express');
const router = express.Router();
const { liveSearch } = require('../services/nvd.service');
const { fetchEpssScores } = require('../services/epss.service');
const { enrichWithKev } = require('../services/cisa-kev.service');
const { computePriorityScore } = require('../services/priority.service');
const cache = require('../services/cache.service');

const NVD_MAX_RANGE_DAYS = 119;
const CHUNK_DELAY_MS = 1200; // safe gap between chunked NVD calls

// Split a date range into chunks of maxDays
function chunkDateRange(from, to, maxDays = NVD_MAX_RANGE_DAYS) {
  const chunks = [];
  let start = new Date(from);
  const end = new Date(to);
  while (start <= end) {
    const chunkEnd = new Date(Math.min(
      start.getTime() + maxDays * 86400000,
      end.getTime()
    ));
    chunks.push({
      from: start.toISOString().split('T')[0],
      to: chunkEnd.toISOString().split('T')[0],
    });
    start = new Date(chunkEnd.getTime() + 86400000);
  }
  return chunks;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function enrichCves(cves) {
  if (!cves.length) return [];
  const ids = cves.map(c => c.cve_id);
  const [epssData, kevData] = await Promise.all([
    fetchEpssScores(ids),
    enrichWithKev(ids),
  ]);
  return cves.map(cve => {
    const epss = epssData[cve.cve_id] || { score: 0, percentile: 0 };
    const kev = kevData[cve.cve_id] || { inKev: cve.in_cisa_kev || false };
    return {
      ...cve,
      epss_score: epss.score,
      epss_percentile: epss.percentile,
      in_cisa_kev: kev.inKev,
      priority_score: computePriorityScore({
        cvssScore: cve.cvss_v3_score,
        severity: cve.severity,
        epssScore: epss.score,
        inKev: kev.inKev,
        publishedAt: cve.published_at,
      }),
    };
  });
}

router.get('/', async (req, res) => {
  try {
    const { q, cpe, id, severity, from, to, page = 1, limit = 20 } = req.query;

    if (!q && !cpe && !id) {
      return res.status(400).json({ error: 'Inserisci almeno uno tra: q (keyword), cpe, id' });
    }

    if (from && to && new Date(to) < new Date(from)) {
      return res.status(400).json({ error: 'La data "Al" deve essere dopo "Dal"' });
    }

    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const pageNum = Math.max(1, parseInt(page));

    // Calculate date chunks
    const chunks = (from && to) ? chunkDateRange(from, to) : [{ from, to }];
    const chunked = chunks.length > 1;

    const cacheKey = `live:${Buffer.from(JSON.stringify({ q, cpe, id, severity, from, to, pageNum, limitNum })).toString('base64').slice(0, 80)}`;
    const cached = await cache.get(cacheKey);
    if (cached) return res.json({ ...cached, cached: true });

    // Fetch all chunks and merge
    const allCves = [];
    let grandTotal = 0;

    for (let i = 0; i < chunks.length; i++) {
      if (i > 0) await sleep(CHUNK_DELAY_MS);
      const chunk = chunks[i];

      const result = await liveSearch({
        keyword: q,
        cpeName: cpe,
        cveId: id,
        severity,
        pubStartDate: chunk.from ? `${chunk.from}T00:00:00.000` : undefined,
        pubEndDate: chunk.to ? `${chunk.to}T23:59:59.999` : undefined,
        // For chunked requests: fetch all then paginate in memory
        resultsPerPage: chunked ? 2000 : limitNum,
        startIndex: chunked ? 0 : (pageNum - 1) * limitNum,
      });

      grandTotal += result.total;
      allCves.push(...result.cves);
    }

    // Deduplicate by cve_id
    const seen = new Set();
    const unique = allCves.filter(c => {
      if (seen.has(c.cve_id)) return false;
      seen.add(c.cve_id);
      return true;
    });

    // For chunked requests, sort by published_at desc and paginate in memory
    let pageData;
    let total;
    if (chunked) {
      unique.sort((a, b) => new Date(b.published_at || 0) - new Date(a.published_at || 0));
      total = unique.length;
      const offset = (pageNum - 1) * limitNum;
      pageData = unique.slice(offset, offset + limitNum);
    } else {
      total = grandTotal;
      pageData = unique;
    }

    const enriched = await enrichCves(pageData);

    const response = {
      data: enriched,
      total,
      page: pageNum,
      limit: limitNum,
      pages: Math.ceil(total / limitNum),
      chunked,
      chunks_fetched: chunks.length,
    };

    await cache.set(cacheKey, response, 120);
    res.json(response);
  } catch (err) {
    if (err.message === 'NVD_RATE_LIMIT') {
      return res.status(429).json({ error: 'NVD sta limitando le richieste. Attendi qualche secondo e riprova.' });
    }
    console.error('Live search error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
