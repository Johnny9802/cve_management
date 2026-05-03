'use strict';

const { EventEmitter } = require('events');
const db = require('../database/postgres');

// Keys that may be managed via the GUI.
const ALLOWED_KEYS = ['NVD_API_KEY', 'ALLOWED_ORIGIN'];

// Keys whose values are masked in API responses.
const SENSITIVE_KEYS = new Set(['NVD_API_KEY']);

// In-process memo so getConfig() doesn't hit the DB on every NVD request.
const memo = new Map(); // key → { value, expiresAt }
const MEMO_TTL_MS = 30_000;

// EventEmitter: subscribers (e.g. nvd.service) listen for 'change' to invalidate caches.
const events = new EventEmitter();

/**
 * Read a config value.
 * Priority: in-process memo → DB → process.env → null.
 */
async function getConfig(key) {
  const cached = memo.get(key);
  if (cached && Date.now() < cached.expiresAt) return cached.value;

  try {
    const { rows } = await db.query(
      'SELECT value FROM app_config WHERE key = $1',
      [key]
    );
    const dbValue = rows.length ? rows[0].value : undefined;
    // Treat empty strings the same as null — an empty env var is not configured
    const value = (dbValue !== undefined && dbValue !== null && dbValue !== '')
      ? dbValue
      : (process.env[key] || null);

    memo.set(key, { value, expiresAt: Date.now() + MEMO_TTL_MS });
    return value;
  } catch {
    // DB unavailable — fall back to env
    return process.env[key] || null;
  }
}

/**
 * Persist a config value to the DB and immediately invalidate the memo.
 */
async function setConfig(key, value, updatedBy = 'system') {
  if (!ALLOWED_KEYS.includes(key)) {
    const err = new Error(`Unknown config key "${key}". Allowed: ${ALLOWED_KEYS.join(', ')}`);
    err.statusCode = 400;
    throw err;
  }

  const { rows } = await db.query(
    `INSERT INTO app_config (key, value, updated_at, updated_by)
     VALUES ($1, $2, NOW(), $3)
     ON CONFLICT (key) DO UPDATE SET
       value      = EXCLUDED.value,
       updated_at = NOW(),
       updated_by = EXCLUDED.updated_by
     RETURNING key, updated_at`,
    [key, value || null, updatedBy]
  );

  invalidate(key);
  events.emit('change', { key, value });
  return rows[0];
}

/**
 * List all config entries with masked sensitive values.
 * source: 'db' if set in DB, 'env' if only in env, 'unset' if neither.
 */
async function listConfig() {
  let dbRows = [];
  try {
    const { rows } = await db.query('SELECT key, value, updated_at, updated_by FROM app_config ORDER BY key');
    dbRows = rows;
  } catch { /* DB unavailable — show env-only view */ }

  return ALLOWED_KEYS.map((key) => {
    const row = dbRows.find((r) => r.key === key);
    // Normalise: empty strings are treated as "not set" in both DB and env
    const dbValue  = (row?.value && row.value !== '') ? row.value : null;
    const envValue = (process.env[key] && process.env[key] !== '') ? process.env[key] : null;

    let source;
    if (dbValue !== null)  source = 'db';
    else if (envValue !== null) source = 'env';
    else source = 'unset';

    const rawValue = dbValue ?? envValue;
    const isSet = rawValue !== null;
    const maskedValue = isSet && SENSITIVE_KEYS.has(key) ? maskValue(rawValue) : null;

    return {
      key,
      value_masked: maskedValue,
      is_set: isSet,
      source,
      updated_at: row?.updated_at ?? null,
      description: KEY_DESCRIPTIONS[key] || '',
    };
  });
}

/** Drop memo entry for a key (or all if key omitted). */
function invalidate(key) {
  if (key) memo.delete(key);
  else memo.clear();
}

function maskValue(v) {
  if (!v || v.length <= 4) return '••••';
  return '•'.repeat(v.length - 4) + v.slice(-4);
}

const KEY_DESCRIPTIONS = {
  NVD_API_KEY: 'NVD API key. Without key: 5 req/30s. With key: 50 req/30s. Get one free at nvd.nist.gov/developers',
  ALLOWED_ORIGIN: 'CORS allowed origin for the frontend (e.g. https://secops.example.com). Restart required.',
};

module.exports = { getConfig, setConfig, listConfig, invalidate, events, ALLOWED_KEYS };
