'use strict';

const axios = require('axios');
const db = require('../database/postgres');
const cache = require('./cache.service');
const config = require('../config/config');
const { getConfig } = require('./config.service');

const PROBE_TIMEOUT_MS = 8000;
const DEGRADED_LATENCY_MS = 3000;

function timeout(ms) {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error('probe_timeout')), ms)
  );
}

async function timed(fn) {
  const start = Date.now();
  await fn();
  return Date.now() - start;
}

// ── Individual probes ────────────────────────────────────────────────────────

async function probeNvd() {
  try {
    const apiKey = await getConfig('NVD_API_KEY');
    const headers = apiKey ? { apiKey } : {};
    const ms = await timed(() =>
      Promise.race([
        axios.get(config.nvd.baseUrl, { headers, params: { resultsPerPage: 1 }, timeout: PROBE_TIMEOUT_MS }),
        timeout(PROBE_TIMEOUT_MS),
      ])
    );
    return { status: ms > DEGRADED_LATENCY_MS ? 'degraded' : 'ok', latency_ms: ms };
  } catch (err) {
    return { status: 'error', latency_ms: null, detail: err.message };
  }
}

async function probeCircl() {
  // Use a single known CVE as a lightweight probe — much faster than /api/last.
  // Extend timeout to 12 s: CIRCL is a free community service and can be slow.
  // A timeout means "slow / degraded", not "down" — searches still work via
  // the stale-cache fallback in circl.routes.js.
  const CIRCL_TIMEOUT = 12000;
  try {
    const ms = await timed(() =>
      Promise.race([
        axios.get('https://cve.circl.lu/api/cve/CVE-2021-44228', { timeout: CIRCL_TIMEOUT }),
        timeout(CIRCL_TIMEOUT),
      ])
    );
    return { status: ms > DEGRADED_LATENCY_MS ? 'degraded' : 'ok', latency_ms: ms };
  } catch (err) {
    const status = err.response?.status;
    // probe_timeout → degraded (service is slow but may still work for searches)
    if (!status || err.message === 'probe_timeout') {
      return {
        status: 'degraded',
        latency_ms: null,
        detail: 'Risposta lenta (>12s) — le ricerche funzionano tramite cache',
      };
    }
    if (status >= 500) {
      return { status: 'degraded', latency_ms: null, detail: `HTTP ${status} — servizio temporaneamente instabile` };
    }
    return { status: 'error', latency_ms: null, detail: `HTTP ${status}` };
  }
}

async function probeEpss() {
  try {
    const ms = await timed(() =>
      Promise.race([
        axios.get(config.epss.baseUrl, { params: { envelope: true, limit: 1 }, timeout: PROBE_TIMEOUT_MS }),
        timeout(PROBE_TIMEOUT_MS),
      ])
    );
    return { status: ms > DEGRADED_LATENCY_MS ? 'degraded' : 'ok', latency_ms: ms };
  } catch (err) {
    return { status: 'error', latency_ms: null, detail: err.message };
  }
}

async function probeKev() {
  try {
    // Lightweight: check if the cached KEV feed is fresh (< 6 h old)
    const cached = await cache.get('cisa:kev:full');
    if (cached) return { status: 'ok', latency_ms: 0, detail: `${cached.ids?.length ?? '?'} entries cached` };

    // Cache miss — try a live fetch (HEAD is not supported, use GET with timeout)
    const start = Date.now();
    await Promise.race([
      axios.get(config.cisaKev.url, { timeout: PROBE_TIMEOUT_MS }),
      timeout(PROBE_TIMEOUT_MS),
    ]);
    return { status: 'ok', latency_ms: Date.now() - start };
  } catch (err) {
    return { status: 'error', latency_ms: null, detail: err.message };
  }
}

async function probeRedis() {
  try {
    const start = Date.now();
    await Promise.race([
      cache.set('__health_probe__', 1, 5),
      timeout(PROBE_TIMEOUT_MS),
    ]);
    const ms = Date.now() - start;
    return { status: ms > DEGRADED_LATENCY_MS ? 'degraded' : 'ok', latency_ms: ms };
  } catch (err) {
    return { status: 'error', latency_ms: null, detail: err.message };
  }
}

async function probeDatabase() {
  try {
    const start = Date.now();
    await Promise.race([db.query('SELECT 1'), timeout(PROBE_TIMEOUT_MS)]);
    const ms = Date.now() - start;
    return { status: ms > DEGRADED_LATENCY_MS ? 'degraded' : 'ok', latency_ms: ms };
  } catch (err) {
    return { status: 'error', latency_ms: null, detail: err.message };
  }
}

// ── Aggregate ────────────────────────────────────────────────────────────────

const PROBES = { nvd: probeNvd, circl: probeCircl, epss: probeEpss, kev: probeKev, redis: probeRedis, database: probeDatabase };

/**
 * Run all probes in parallel. Returns the full status object.
 * Never throws — each probe catches its own errors.
 */
async function checkAll() {
  const results = await Promise.allSettled(
    Object.entries(PROBES).map(async ([name, fn]) => ({ name, result: await fn() }))
  );

  const status = {};
  for (const r of results) {
    if (r.status === 'fulfilled') {
      status[r.value.name] = r.value.result;
    } else {
      status[r.reason?.name || 'unknown'] = { status: 'error', latency_ms: null, detail: String(r.reason) };
    }
  }

  return { ...status, checked_at: new Date().toISOString() };
}

/**
 * Run a single named probe. Returns the probe result.
 */
async function checkOne(name) {
  const fn = PROBES[name];
  if (!fn) {
    const err = new Error(`Unknown service "${name}". Valid: ${Object.keys(PROBES).join(', ')}`);
    err.statusCode = 400;
    throw err;
  }
  return fn();
}

module.exports = { checkAll, checkOne, PROBES };
