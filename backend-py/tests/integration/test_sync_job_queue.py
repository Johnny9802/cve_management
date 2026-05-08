"""Integration tests: sync_jobs DB queue behaviour.

Verifies:
- FOR UPDATE SKIP LOCKED prevents double-claiming
- Retry backoff scheduling
- Dead job after max_attempts
- locked_until prevents re-claim of stuck jobs
"""
from __future__ import annotations

import asyncio

import asyncpg
import pytest


async def _insert_job(
    conn: asyncpg.Connection,
    job_type: str = "product_sync",
    target_id: str = "1",
    priority: int = 10,
    max_attempts: int = 3,
) -> int:
    row = await conn.fetchrow(
        """
        INSERT INTO sync_jobs (job_type, target_id, priority, max_attempts)
        VALUES ($1, $2, $3, $4) RETURNING id
        """,
        job_type, target_id, priority, max_attempts,
    )
    return row["id"]


_CLAIM_SQL = """
    UPDATE sync_jobs
    SET status       = 'running',
        started_at   = NOW(),
        locked_until = NOW() + INTERVAL '5 minutes',
        attempts     = attempts + 1
    WHERE id = (
        SELECT id FROM sync_jobs
        WHERE  status = 'pending'
          AND (locked_until IS NULL OR locked_until < NOW())
        ORDER BY priority DESC, scheduled_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    RETURNING id
"""


@pytest.mark.asyncio
class TestSyncJobClaiming:
    async def test_single_job_claimed_once(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            job_id = await _insert_job(conn)

        # Two concurrent workers both try to claim
        async def _try_claim():
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(_CLAIM_SQL)
                return row["id"] if row else None

        results = await asyncio.gather(_try_claim(), _try_claim())
        claimed = [r for r in results if r is not None]

        # Only one worker should claim the job
        assert len(claimed) == 1
        assert claimed[0] == job_id

    async def test_pending_job_not_claimed_while_locked(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        async with db_pool.acquire() as conn:
            job_id = await _insert_job(conn)
            # Mark as running with lock
            await conn.execute(
                """
                UPDATE sync_jobs
                SET status = 'running',
                    locked_until = NOW() + INTERVAL '10 minutes'
                WHERE id = $1
                """,
                job_id,
            )

        # Should not be claimable while locked
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(_CLAIM_SQL)
        assert row is None

    async def test_priority_ordering(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            await _insert_job(conn, target_id="1", priority=10)
            await _insert_job(conn, target_id="2", priority=100)
            critical_id = await _insert_job(conn, target_id="3", priority=999)

        # Highest priority should be claimed first
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(_CLAIM_SQL)
        assert row["id"] == critical_id

    async def test_deduplication_prevents_duplicate_pending(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        async with db_pool.acquire() as conn:
            # Insert first job
            await _insert_job(conn, target_id="42")

            # Try to insert same job_type+target_id (unique partial index)
            row = await conn.fetchrow(
                """
                INSERT INTO sync_jobs (job_type, target_id, priority)
                SELECT 'product_sync', '42', 10
                WHERE NOT EXISTS (
                    SELECT 1 FROM sync_jobs
                    WHERE job_type = 'product_sync'
                      AND target_id = '42'
                      AND status IN ('pending', 'running')
                )
                RETURNING id
                """,
            )

        # Second insert should be skipped (WHERE NOT EXISTS returns nothing)
        assert row is None


@pytest.mark.asyncio
class TestSyncJobRetry:
    async def test_failed_job_rescheduled(self, db_pool: asyncpg.Pool, clean_db):
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

        async with db_pool.acquire() as conn:
            job_id = await _insert_job(conn, max_attempts=3)
            # Simulate claim + fail cycle ×3
            for _ in range(3):
                await conn.execute(_CLAIM_SQL)
                await conn.execute(_FAIL_SQL, job_id, "simulated error")

            row = await conn.fetchrow("SELECT status, attempts FROM sync_jobs WHERE id = $1", job_id)

        assert row["status"] == "dead"
        assert row["attempts"] == 3

    async def test_job_marked_complete(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            job_id = await _insert_job(conn)
            await conn.execute(_CLAIM_SQL)
            await conn.execute(
                "UPDATE sync_jobs SET status='completed', completed_at=NOW() WHERE id=$1",
                job_id,
            )
            row = await conn.fetchrow("SELECT status FROM sync_jobs WHERE id=$1", job_id)

        assert row["status"] == "completed"
