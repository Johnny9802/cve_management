const axios = require('axios');
const config = require('../config/config');
const cache = require('./cache.service');

const CPE_API = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';
const headers = config.nvd.apiKey ? { apiKey: config.nvd.apiKey } : {};

async function suggestCpes(keyword, { limit = 15 } = {}) {
  if (!keyword || keyword.trim().length < 2) return [];

  const cacheKey = `cpe:suggest:${keyword.trim().toLowerCase()}`;
  const cached = await cache.get(cacheKey);
  if (cached) return cached;

  try {
    // Fetch up to 500 to find non-deprecated entries even when they appear late
    // (e.g. nginx: old igor_sysoev:nginx CPEs fill the first 100+ slots)
    const allProducts = [];
    for (let startIndex = 0; startIndex < 500; startIndex += 100) {
      const resp = await axios.get(CPE_API, {
        headers,
        params: { keywordSearch: keyword.trim(), resultsPerPage: 100, startIndex },
        timeout: 15000,
      });
      const batch = resp.data?.products || [];
      allProducts.push(...batch);
      const total = resp.data?.totalResults || 0;
      if (allProducts.length >= total || batch.length === 0) break;

      // Stop early if we already have enough non-deprecated entries
      const nonDep = allProducts.filter(p => !p.cpe?.deprecated);
      if (nonDep.length >= limit * 3) break;
    }

    const seen = new Map();        // groupKey → best non-deprecated entry
    const seenDeprecated = new Map(); // fallback

    for (const p of allProducts) {
      const cpe = p.cpe || {};
      const cpeName = cpe.cpeName || '';
      const parts = cpeName.split(':');
      if (parts.length < 6) continue;

      const part    = parts[2];
      const vendor  = parts[3];
      const product = parts[4];
      const version = parts[5];

      // Group by vendor:product to collapse architecture/build variants
      const groupKey = `${vendor}:${product}`;
      const searchCpe = (version === '*' || !version)
        ? `cpe:2.3:${part}:${vendor}:${product}`
        : `cpe:2.3:${part}:${vendor}:${product}:${version}`;

      const titles = cpe.titles || [];
      const title = (titles.find(t => t.lang === 'en') || titles[0])?.title || product;
      const cleanTitle = title
        .replace(/\s+on\s+(x64|x86|ARM64|arm64|x86_64)$/i, '')
        .replace(/\s+\d{10,}$/, '') // strip build numbers from end
        .trim();

      const entry = { cpeName: searchCpe, title: cleanTitle, vendor, product, part };

      if (!cpe.deprecated) {
        if (!seen.has(groupKey)) seen.set(groupKey, entry);
      } else {
        if (!seenDeprecated.has(groupKey)) seenDeprecated.set(groupKey, entry);
      }
    }

    // Prefer non-deprecated; include deprecated only if primary is empty or sparse
    const primary   = Array.from(seen.values());
    const secondary = Array.from(seenDeprecated.values());
    const results   = primary.length > 0
      ? primary.slice(0, limit)
      : secondary.slice(0, limit);

    await cache.set(cacheKey, results, 3600);
    return results;
  } catch (err) {
    console.error('CPE suggest error:', err.message);
    return [];
  }
}

module.exports = { suggestCpes };
