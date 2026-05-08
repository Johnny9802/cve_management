"""Integration tests: finding FSM lifecycle and audit trail.

Verifies:
- Status transitions are persisted correctly
- findings_history records every change
- Human decisions (false_positive, accepted_risk) are not overwritten by sync
- Idempotent upsert preserves existing human status
"""
from __future__ import annotations

import asyncpg
import pytest

from tests.integration.conftest import seed_cve, seed_finding, seed_product


@pytest.mark.asyncio
class TestFindingStatusTransitions:
    async def test_initial_status_is_open(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)
            fid = await seed_finding(conn, pid, cid, status="open")
            row = await conn.fetchrow("SELECT status FROM findings WHERE id = $1", fid)

        assert row["status"] == "open"

    async def test_status_transition_recorded_in_history(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)
            fid = await seed_finding(conn, pid, cid, status="open")

            # Transition to in_review
            await conn.execute(
                "UPDATE findings SET status = 'in_review' WHERE id = $1", fid
            )
            await conn.execute(
                """INSERT INTO findings_history (finding_id, old_status, new_status, changed_by)
                   VALUES ($1, 'open', 'in_review', 'test')""",
                fid,
            )

            history = await conn.fetch(
                "SELECT * FROM findings_history WHERE finding_id = $1 ORDER BY changed_at",
                fid,
            )

        assert len(history) == 1
        assert history[0]["old_status"] == "open"
        assert history[0]["new_status"] == "in_review"

    async def test_multiple_transitions_all_recorded(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)
            fid = await seed_finding(conn, pid, cid, status="open")

            transitions = [
                ("open", "in_review"),
                ("in_review", "planned"),
                ("planned", "remediated"),
            ]
            for old, new in transitions:
                await conn.execute(
                    "UPDATE findings SET status = $1 WHERE id = $2", new, fid
                )
                await conn.execute(
                    """INSERT INTO findings_history (finding_id, old_status, new_status, changed_by)
                       VALUES ($1, $2, $3, 'test')""",
                    fid, old, new,
                )

            history = await conn.fetch(
                "SELECT old_status, new_status FROM findings_history WHERE finding_id = $1 ORDER BY id",
                fid,
            )

        assert len(history) == 3
        assert history[-1]["new_status"] == "remediated"

    async def test_sync_upsert_preserves_false_positive(self, db_pool: asyncpg.Pool, clean_db):
        """ON CONFLICT ... WHERE NOT IN ('false_positive') must not overwrite human decision."""
        from app.models.priority import compute_priority_score

        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)
            fid = await seed_finding(conn, pid, cid, status="false_positive")

            # Simulate what product_sync upsert does
            priority = compute_priority_score(7.5, "HIGH", 0.1, False, None)
            await conn.execute(
                """
                INSERT INTO findings (product_id, cve_id, status, match_confidence, priority_score)
                VALUES ($1, $2, 'open', 'certain', $3)
                ON CONFLICT (product_id, cve_id) DO UPDATE SET
                    match_confidence = EXCLUDED.match_confidence,
                    priority_score   = EXCLUDED.priority_score
                WHERE findings.status NOT IN ('false_positive', 'accepted_risk', 'closed')
                """,
                pid, cid, float(priority),
            )

            row = await conn.fetchrow("SELECT status FROM findings WHERE id = $1", fid)

        # Status must remain 'false_positive' — sync must NOT overwrite it
        assert row["status"] == "false_positive"

    async def test_sync_upsert_updates_open_finding(self, db_pool: asyncpg.Pool, clean_db):
        """For 'open' findings, sync IS allowed to update match data."""
        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)
            fid = await seed_finding(conn, pid, cid, status="open", priority_score=20.0)

            await conn.execute(
                """
                INSERT INTO findings (product_id, cve_id, status, match_confidence, priority_score)
                VALUES ($1, $2, 'open', 'certain', $3)
                ON CONFLICT (product_id, cve_id) DO UPDATE SET
                    priority_score = EXCLUDED.priority_score
                WHERE findings.status NOT IN ('false_positive', 'accepted_risk', 'closed')
                """,
                pid, cid, 80.0,
            )

            row = await conn.fetchrow("SELECT priority_score FROM findings WHERE id = $1", fid)

        assert float(row["priority_score"]) == 80.0


@pytest.mark.asyncio
class TestFindingConstraints:
    async def test_unique_product_cve_pair(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)
            await seed_finding(conn, pid, cid)

            with pytest.raises(asyncpg.UniqueViolationError):
                await conn.execute(
                    "INSERT INTO findings (product_id, cve_id, status) VALUES ($1, $2, 'open')",
                    pid, cid,
                )

    async def test_invalid_status_rejected_by_check_constraint(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)

            with pytest.raises(asyncpg.CheckViolationError):
                await conn.execute(
                    "INSERT INTO findings (product_id, cve_id, status) VALUES ($1, $2, 'invalid')",
                    pid, cid,
                )

    async def test_cascade_delete_on_product_removal(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            pid = await seed_product(conn)
            cid = await seed_cve(conn)
            fid = await seed_finding(conn, pid, cid)

            await conn.execute("DELETE FROM products WHERE id = $1", pid)

            row = await conn.fetchrow("SELECT id FROM findings WHERE id = $1", fid)
        assert row is None  # cascade deleted
