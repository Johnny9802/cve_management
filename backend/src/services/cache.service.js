const Redis = require('ioredis');
const config = require('../config/config');

let client = null;

function getClient() {
  if (!client) {
    client = new Redis(config.redis.url, {
      password: config.redis.password || undefined,
      lazyConnect: true,
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => Math.min(times * 100, 3000),
    });
    client.on('error', (err) => console.error('Redis error:', err.message));
  }
  return client;
}

async function get(key) {
  try {
    const val = await getClient().get(key);
    return val ? JSON.parse(val) : null;
  } catch {
    return null;
  }
}

async function set(key, value, ttlSeconds) {
  try {
    await getClient().set(key, JSON.stringify(value), 'EX', ttlSeconds);
  } catch {}
}

async function del(key) {
  try {
    await getClient().del(key);
  } catch {}
}

async function delPattern(pattern) {
  try {
    const c = getClient();
    // SCAN instead of KEYS: non-blocking O(1) per call, safe in production.
    const keys = [];
    let cursor = '0';
    do {
      const [next, batch] = await c.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      keys.push(...batch);
      cursor = next;
    } while (cursor !== '0');
    if (keys.length) await c.del(...keys);
  } catch {}
}

// Returns the value stored under `key + ':stale'` — a long-lived fallback copy
// written by setWithStale(). Never returns null even if expired.
async function getStale(key) {
  return get(key + ':stale');
}

// Writes `key` with `ttlSeconds` AND a companion `key:stale` with `staleTtlSeconds` (24 h default).
// Use this for external API responses where a stale copy is better than a 503.
async function setWithStale(key, value, ttlSeconds, staleTtlSeconds = 86400) {
  await Promise.all([
    set(key, value, ttlSeconds),
    set(key + ':stale', value, staleTtlSeconds),
  ]);
}

module.exports = { get, set, del, delPattern, getStale, setWithStale };
