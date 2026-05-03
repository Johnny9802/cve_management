'use strict';

/**
 * DB-backed sync worker.
 *
 * Uses PostgreSQL `SELECT … FOR UPDATE SKIP LOCKED` so multiple instances
 * never pick the same job. Safe for single-instance and multi-instance deploys.
 *
 * Job types:
 *   product_sync  — fetch CVEs from NVD for one product
 *
 * Lifecycle:
 *   enqueueProductSync() → pending → (worker picks up) → running → done | failed
 *   After max_attempts: status = 'dead'
 */

const db   = require('../database/postgres');
const { syncProduct } = require('./product-sync.service');

const WORKER_ID   = `worker-${process.pid}`;
const TICK_MS     = 2000;   // how often to poll for new jobs
const LOCK_TTL_S  = 300;    // claim timeout: 5 min (prevents stuck jobs)
const BASE_BACKOFF_S = 30;  // retry delay: 30s, 60s, 120s …

let running  = false;
let tickTimer = null;

// ── Enqueue ───────────────────────────────────────────────────────────────────

/**
 * Enqueue a product sync. De-duplicated: if a pending/running job already
 * exists for this product, returns the existing job id.
 */
async function enqueueProductSync(productId, priority = 50) {
  try {
    const { rows } = await db.query(`
      INSERT INTO sync_jobs (job_type, target_id, priority, scheduled_at)
      VALUES ('product_sync', $1, $2, NOW())
      ON CONFLICT (job_type, target_id) WHERE status IN ('pending','running')
      DO NOTHING
      RETURNING id
    `, [productId, priority]);

    if (rows.length) {
      await db.query(
        `UPDATE products SET sync_status='pending', sync_started_at=NULL, sync_error=NULL WHERE id=$1`,
        [productId]
      );
      return rows[0].id;
    }

    // Already queued — return existing job id
    const existing = await db.query(
      `SELECT id FROM sync_jobs WHERE job_type='product_sync' AND target_id=$1 AND status IN ('pending','running') LIMIT 1`,
      [productId]
    );
    return existing.rows[0]?.id ?? null;
  } catch (err) {
    console.error('enqueueProductSync error:', err.message);
    return null;
  }
}

// ── Worker loop ───────────────────────────────────────────────────────────────

async function claimNextJob() {
  const { rows } = await db.query(`
    UPDATE sync_jobs
    SET status       = 'running',
        started_at   = NOW(),
        locked_by    = $1,
        locked_until = NOW() + ($2 || ' seconds')::INTERVAL,
        attempts     = attempts + 1,
        updated_at   = NOW()
    WHERE id = (
      SELECT id FROM sync_jobs
      WHERE status IN ('pending','failed')
        AND scheduled_at <= NOW()
        AND attempts < max_attempts
      ORDER BY priority ASC, scheduled_at ASC
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    RETURNING *
  `, [WORKER_ID, LOCK_TTL_S]);
  return rows[0] || null;
}

async function completeJob(id, stats = {}) {
  await db.query(`
    UPDATE sync_jobs
    SET status        = 'done',
        completed_at  = NOW(),
        locked_by     = NULL,
        locked_until  = NULL,
        cves_fetched  = $2,
        cves_filtered = $3,
        cves_linked   = $4,
        error_message = NULL,
        updated_at    = NOW()
    WHERE id = $1
  `, [id, stats.fetched ?? 0, stats.filtered ?? 0, stats.linked ?? 0]);
}

async function failJob(id, err, maxAttempts) {
  const { rows } = await db.query(`
    UPDATE sync_jobs
    SET status        = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'failed' END,
        completed_at  = CASE WHEN attempts >= max_attempts THEN NOW() ELSE NULL END,
        error_message = $2,
        locked_by     = NULL,
        locked_until  = NULL,
        -- exponential back-off: 30s * 2^(attempts-1)
        scheduled_at  = CASE WHEN attempts < max_attempts
                             THEN NOW() + ($3 * POWER(2, attempts - 1) || ' seconds')::INTERVAL
                             ELSE scheduled_at END,
        updated_at    = NOW()
    WHERE id = $1
    RETURNING status, target_id, job_type
  `, [id, err.message?.substring(0, 500) || 'unknown error', BASE_BACKOFF_S]);

  return rows[0];
}

async function runJob(job) {
  if (job.job_type === 'product_sync') {
    // Update product status → running
    await db.query(
      `UPDATE products SET sync_status='running', sync_started_at=NOW(), sync_error=NULL WHERE id=$1`,
      [job.target_id]
    );

    const result = await syncProduct(job.target_id);

    await db.query(
      `UPDATE products
       SET sync_status='done', sync_finished_at=NOW(),
           sync_cves_fetched=$2, sync_cves_linked=$3, sync_error=NULL
       WHERE id=$1`,
      [job.target_id, result.synced + (result.filtered ?? 0), result.synced]
    );

    return { fetched: result.synced + (result.filtered ?? 0), filtered: result.filtered ?? 0, linked: result.synced };
  }
  throw new Error(`Unknown job type: ${job.job_type}`);
}

async function tick() {
  try {
    const job = await claimNextJob();
    if (!job) return; // nothing to do

    console.log(`[sync-worker] claimed job ${job.id} (${job.job_type}, target=${job.target_id}, attempt ${job.attempts})`);
    try {
      const stats = await runJob(job);
      await completeJob(job.id, stats);
      console.log(`[sync-worker] job ${job.id} done — ${stats.linked} CVEs linked`);
    } catch (err) {
      console.error(`[sync-worker] job ${job.id} failed:`, err.message);
      const result = await failJob(job.id, err);

      if (job.job_type === 'product_sync' && job.target_id) {
        const isFinal = result?.status === 'dead';
        await db.query(
          `UPDATE products SET sync_status=$2, sync_error=$3, sync_finished_at=NOW() WHERE id=$1`,
          [job.target_id, isFinal ? 'failed' : 'pending', err.message?.substring(0, 500)]
        );
      }
    }
  } catch (err) {
    console.error('[sync-worker] tick error:', err.message);
  }
}

function start() {
  if (running) return;
  running = true;
  console.log(`[sync-worker] started (${WORKER_ID})`);

  const loop = async () => {
    if (!running) return;
    await tick();
    tickTimer = setTimeout(loop, TICK_MS);
  };
  loop();
}

function stop() {
  running = false;
  if (tickTimer) clearTimeout(tickTimer);
  console.log('[sync-worker] stopped');
}

module.exports = { start, stop, enqueueProductSync };
