const axios = require('axios');
const config = require('../config/config');
const cache = require('./cache.service');
const { retry } = require('../utils/retry');

// Fetch EPSS scores for a batch of CVE IDs (max 100 per call)
async function fetchEpssScores(cveIds) {
  if (!cveIds || cveIds.length === 0) return {};

  const cacheKey = `epss:${cveIds.sort().join(',')}`.substring(0, 200);
  const cached = await cache.get(cacheKey);
  if (cached) return cached;

  try {
    const chunks = chunkArray(cveIds, 100);
    const results = {};

    for (const chunk of chunks) {
      const response = await retry(() => axios.get(config.epss.baseUrl, {
        params: { cve: chunk.join(','), limit: 100 },
        timeout: 10000,
      }), { attempts: 3, baseDelayMs: 800 });

      for (const item of response.data?.data || []) {
        results[item.cve] = {
          score: parseFloat(item.epss) || 0,
          percentile: parseFloat(item.percentile) || 0,
        };
      }
    }

    await cache.set(cacheKey, results, config.cache.ttl.epss);
    return results;
  } catch (err) {
    console.error('EPSS fetch error:', err.message);
    return {};
  }
}

function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

module.exports = { fetchEpssScores };
