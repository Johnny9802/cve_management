"""DB-backed sync job queue poller.

Uses FOR UPDATE SKIP LOCKED to safely claim jobs in multi-worker scenarios.
Called by APScheduler every POLL_INTERVAL_SECONDS.

Job types dispatched:
  product_sync — runs product_sync.sync_product() for the target product ID
  (delta_sync, epss_refresh, kev_refresh handled by ingestion workers directly)

Retry policy:
  - Max attempts: job.max_attempts (default 3)
  - After max_attempts: status → 'dead', error_message stored
  - Backoff: 30s × 2^(attempts-1) via scheduled_at update on failure
"""
from __future__ import annotations

import asyncpg
import structlog
from redis.asyncio import Redis

from app.workers.product_sync import sync_product

logger = structlog.get_logger(__name__)

POLL_INTERVAL_SECONDS = 5
_LOCK_TTL = "5 minutes"

_CLAIM_SQL = f"""
    UPDATE sync_jobs
    SET status       = 'running',
        started_at   = NOW(),
        locked_until = NOW() + INTERVAL '{_LOCK_TTL}',
        attempts     = attempts + 1
    WHERE id = (
        SELECT id FROM sync_jobs
        WHERE  status = 'pending'
          AND (locked_until IS NULL OR locked_until < NOW())
        ORDER BY priority DESC, scheduled_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    RETURNING *
"""

_COMPLETE_SQL = """
    UPDATE sync_jobs
    SET status       = 'completed',
        completed_at = NOW(),
        error_message = NULL
    WHERE id = $1
"""

_FAIL_SQL = """
    UPDATE sync_jobs
    SET status        = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'pending' END,
        error_message = $2,
        scheduled_at  = CASE
            WHEN attempts < max_attempts
            THEN NOW() + (30 * POWER(2, attempts - 1) * INTERVAL '1 second')
            ELSE scheduled_at
        END
    WHERE id = $1
"""


async def process_one_job(pool: asyncpg.Pool, redis: Redis) -> bool:
    """Claim and process one pending job. Returns True if a job was processed."""
    async with pool.acquire() as conn:
        job = await conn.fetchrow(_CLAIM_SQL)

    if not job:
        return False

    job_id = job["id"]
    job_type = job["job_type"]
    target_id = job["target_id"]
    log = logger.bind(job_id=job_id, job_type=job_type, target_id=target_id)
    log.info("sync_job.claimed", attempt=job["attempts"])

    try:
        if job_type == "product_sync" and target_id:
            await sync_product(pool, redis, int(target_id))
        else:
            log.warning("sync_job.unknown_type", job_type=job_type)

        async with pool.acquire() as conn:
            await conn.execute(_COMPLETE_SQL, job_id)
        log.info("sync_job.completed")

    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {str(exc)[:400]}"
        log.error("sync_job.failed", error=error_msg)
        async with pool.acquire() as conn:
            await conn.execute(_FAIL_SQL, job_id, error_msg)

    return True


async def drain_pending_jobs(pool: asyncpg.Pool, redis: Redis) -> int:
    """Process all currently pending jobs in sequence. Returns count processed."""
    count = 0
    while True:
        processed = await process_one_job(pool, redis)
        if not processed:
            break
        count += 1
    return count
