const axios = require('axios');
const config = require('../config/config');
const cache = require('./cache.service');

let kevSet = null;
let kevDetails = {};
let lastFetch = 0;

async function loadKev() {
  const now = Date.now();
  if (kevSet && now - lastFetch < config.cisaKev.refreshInterval) return;

  const cached = await cache.get('cisa:kev:full');
  if (cached) {
    kevSet = new Set(cached.ids);
    kevDetails = cached.details;
    lastFetch = now;
    return;
  }

  try {
    const response = await axios.get(config.cisaKev.url, { timeout: 15000 });
    const vulns = response.data?.vulnerabilities || [];

    kevSet = new Set();
    kevDetails = {};
    for (const v of vulns) {
      kevSet.add(v.cveID);
      kevDetails[v.cveID] = {
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        vendorProject: v.vendorProject,
        product: v.product,
        vulnerabilityName: v.vulnerabilityName,
        requiredAction: v.requiredAction,
      };
    }

    await cache.set('cisa:kev:full', { ids: [...kevSet], details: kevDetails }, config.cache.ttl.kev);
    lastFetch = now;
    console.log(`CISA KEV loaded: ${kevSet.size} entries`);
  } catch (err) {
    console.error('CISA KEV fetch error:', err.message);
    if (!kevSet) kevSet = new Set();
  }
}

async function isInKev(cveId) {
  await loadKev();
  return kevSet?.has(cveId) || false;
}

async function getKevDetails(cveId) {
  await loadKev();
  return kevDetails[cveId] || null;
}

async function enrichWithKev(cveIds) {
  await loadKev();
  const result = {};
  for (const id of cveIds) {
    result[id] = {
      inKev: kevSet?.has(id) || false,
      details: kevDetails[id] || null,
    };
  }
  return result;
}

module.exports = { isInKev, getKevDetails, enrichWithKev, loadKev };
