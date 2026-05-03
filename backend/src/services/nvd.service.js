const axios = require('axios');
const config = require('../config/config');
const { getConfig, events: configEvents } = require('./config.service');

// Build NVD auth headers at call-time so a key set via the GUI takes effect
// immediately (config.service memoises for 30 s and invalidates on change).
async function getHeaders() {
  const key = await getConfig('NVD_API_KEY');
  return key ? { apiKey: key } : {};
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Detect if a string is a CPE name
function isCpe(str) {
  return str && str.toLowerCase().startsWith('cpe:');
}

// Generic paginated NVD fetch
async function fetchNvdPages(params, { maxResults = 500 } = {}) {
  const allCves = [];
  let index = 0;

  while (true) {
    await sleep(config.nvd.requestDelay);
    try {
      const response = await axios.get(config.nvd.baseUrl, {
        headers: await getHeaders(),
        params: { ...params, startIndex: index, resultsPerPage: config.nvd.resultsPerPage },
        timeout: 30000,
      });
      const data = response.data;
      const vulns = data.vulnerabilities || [];
      for (const item of vulns) {
        const parsed = parseNvdCve(item.cve);
        if (parsed) allCves.push(parsed);
      }
      index += vulns.length;
      const total = data.totalResults || 0;
      if (index >= total || index >= maxResults || vulns.length === 0) {
        return { cves: allCves, total };
      }
    } catch (err) {
      if (err.response?.status === 404) break;
      throw err;
    }
  }
  return { cves: allCves, total: allCves.length };
}

// Search by keyword (text search in descriptions)
async function searchCvesByKeyword(keyword, options = {}) {
  console.log(`NVD keyword search: "${keyword}"`);
  const { cves } = await fetchNvdPages({ keywordSearch: keyword }, options);
  return cves;
}

// Search by CPE name (precise product/version match)
async function searchCvesByCpe(cpeName, options = {}) {
  console.log(`NVD CPE search: "${cpeName}"`);
  const { cves } = await fetchNvdPages({ cpeName }, options);
  return cves;
}

// Auto-detect mode: CPE string → CPE search, otherwise keyword search
async function searchCves(query, options = {}) {
  if (isCpe(query)) return searchCvesByCpe(query, options);
  return searchCvesByKeyword(query, options);
}

// Live search: single page, no pagination — for real-time UI.
// No rate-limit delay: live search is single-shot, not batch.
// NVD hard limit: date range max 120 days.
async function liveSearch({ keyword, cpeName, cveId, severity, pubStartDate, pubEndDate, resultsPerPage = 20, startIndex = 0 } = {}) {
  const params = { resultsPerPage, startIndex };
  if (cveId)        params.cveId = cveId.toUpperCase();
  else if (cpeName) params.cpeName = cpeName;
  else if (keyword) params.keywordSearch = keyword;
  else return { cves: [], total: 0 };

  if (severity)     params.cvssV3Severity = severity.toUpperCase();
  if (pubStartDate) params.pubStartDate = pubStartDate;
  if (pubEndDate)   params.pubEndDate = pubEndDate;

  try {
    const response = await axios.get(config.nvd.baseUrl, { headers: await getHeaders(), params, timeout: 30000 });
    const data = response.data;
    const cves = (data.vulnerabilities || []).map((v) => parseNvdCve(v.cve)).filter(Boolean);
    return { cves, total: data.totalResults || 0, startIndex: data.startIndex || 0 };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404) return { cves: [], total: 0 };
    if (status === 429) throw new Error('NVD_RATE_LIMIT');
    throw new Error(`NVD API error ${status || ''}: ${err.message}`);
  }
}

// Fetch a single CVE by ID
async function fetchCveById(cveId) {
  await sleep(config.nvd.requestDelay);
  try {
    const response = await axios.get(config.nvd.baseUrl, {
      headers: await getHeaders(), params: { cveId }, timeout: 15000,
    });
    const vuln = response.data?.vulnerabilities?.[0];
    return vuln ? parseNvdCve(vuln.cve) : null;
  } catch (err) {
    console.error(`NVD fetch error for ${cveId}:`, err.message);
    return null;
  }
}

function parseNvdCve(cve) {
  if (!cve?.id) return null;

  const desc = (cve.descriptions || []).find((d) => d.lang === 'en')?.value || '';
  const cvssV3 = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
  const cvssV2 = cve.metrics?.cvssMetricV2?.[0];

  let severity = cvssV3?.cvssData?.baseSeverity || cvssV2?.baseSeverity || 'NONE';
  severity = severity.toUpperCase();

  const refs = (cve.references || []).map((r) => ({ url: r.url, tags: r.tags || [] }));
  const weaknesses = (cve.weaknesses || []).flatMap((w) => (w.description || []).map((d) => d.value));
  const affectedCpe = extractCpes(cve.configurations || []);

  return {
    cve_id: cve.id,
    description: desc,
    published_at: cve.published,
    last_modified_at: cve.lastModified,
    cvss_v3_score: cvssV3?.cvssData?.baseScore ?? null,
    cvss_v3_vector: cvssV3?.cvssData?.vectorString ?? null,
    cvss_v2_score: cvssV2?.cvssData?.baseScore ?? null,
    severity,
    references: refs,
    weaknesses,
    affected_cpe: affectedCpe,
    // CISA KEV fields from NVD
    in_cisa_kev: !!(cve.cisaExploitAdd),
    cisa_kev_date_added: cve.cisaExploitAdd || null,
    cisa_kev_due_date: cve.cisaActionDue || null,
  };
}

function extractCpes(configurations) {
  const cpes = [];
  for (const cfg of configurations) {
    for (const node of cfg.nodes || []) {
      extractNodeCpes(node, cpes);
    }
  }
  return cpes;
}

// Recursively extracts vulnerable CPE matches from a node and its children.
// NVD configurations can nest nodes with AND/OR logic; we collect all
// vulnerable leaves so the version matcher can evaluate them individually.
function extractNodeCpes(node, cpes) {
  for (const match of node.cpeMatch || []) {
    if (match.vulnerable) {
      cpes.push({
        cpe: match.criteria,
        versionStartIncluding: match.versionStartIncluding || null,
        versionStartExcluding: match.versionStartExcluding || null,
        versionEndIncluding:   match.versionEndIncluding   || null,
        versionEndExcluding:   match.versionEndExcluding   || null,
      });
    }
  }
  for (const child of node.children || []) {
    extractNodeCpes(child, cpes);
  }
}

module.exports = { searchCvesByKeyword, searchCvesByCpe, searchCves, liveSearch, fetchCveById, parseNvdCve, isCpe };
