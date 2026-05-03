"""E2E smoke test — happy path: product creation → sync → findings → lifecycle.

Tests the full system behaviour with real PostgreSQL.
Requires Docker (testcontainers).

Run with:
    uv run pytest tests/integration/test_e2e_smoke.py -v -s
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import asyncpg
import pytest

from tests.integration.conftest import seed_cve
from app.workers.product_sync import sync_product


def _redis_mock():
    redis = AsyncMock()
    redis.scan_iter = AsyncMock(return_value=AsyncMock(__aiter__=lambda s: iter([])))
    return redis


@pytest.mark.asyncio
class TestE2EHappyPath:
    async def test_full_lifecycle(self, db_pool: asyncpg.Pool, clean_db):
        """
        GIVEN a product in inventory and a CVE in the local mirror
        WHEN sync_product() runs
        THEN findings are created with correct priority_score
        AND status can be transitioned through the FSM
        AND audit history is preserved
        """
        # ── Step 1: Insert a product ──────────────────────────────────────────
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO products (name, vendor, version, normalized_cpe)
                VALUES ('nginx', 'nginx', '1.18.0', 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*')
                RETURNING id
                """
            )
            product_id: int = row["id"]

        # ── Step 2: Populate local CVE mirror ────────────────────────────────
        async with db_pool.acquire() as conn:
            await seed_cve(
                conn,
                cve_id="CVE-2024-E2E-001",
                severity="CRITICAL",
                cvss_v3_score=9.8,
                is_kev=True,
            )

        # ── Step 3: Run product sync ─────────────────────────────────────────
        result = await sync_product(db_pool, _redis_mock(), product_id)

        assert result.matched >= 1, "At least one CVE should match nginx 1.18.0"
        assert result.product_id == product_id

        # ── Step 4: Verify finding exists with high priority ─────────────────
        async with db_pool.acquire() as conn:
            finding = await conn.fetchrow(
                """
                SELECT f.*, c.severity
                FROM findings f JOIN cves c ON c.cve_id = f.cve_id
                WHERE f.product_id = $1 AND f.cve_id = 'CVE-2024-E2E-001'
                """,
                product_id,
            )

        assert finding is not None
        assert finding["status"] == "open"
        assert finding["match_confidence"] == "certain"
        # KEV + CRITICAL + recent → high priority score
        assert float(finding["priority_score"]) >= 50

        # ── Step 5: Transition to in_review ──────────────────────────────────
        finding_id = finding["id"]
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE findings SET status = 'in_review' WHERE id = $1", finding_id
                )
                await conn.execute(
                    """INSERT INTO findings_history (finding_id, old_status, new_status, changed_by)
                       VALUES ($1, 'open', 'in_review', 'analyst')""",
                    finding_id,
                )

        # ── Step 6: Transition to remediated ─────────────────────────────────
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE findings SET status = 'remediated' WHERE id = $1", finding_id
                )
                await conn.execute(
                    """INSERT INTO findings_history (finding_id, old_status, new_status, changed_by)
                       VALUES ($1, 'in_review', 'remediated', 'analyst')""",
                    finding_id,
                )

        # ── Step 7: Verify final state and audit trail ───────────────────────
        async with db_pool.acquire() as conn:
            final = await conn.fetchrow("SELECT status FROM findings WHERE id = $1", finding_id)
            history = await conn.fetch(
                "SELECT new_status FROM findings_history WHERE finding_id = $1 ORDER BY id",
                finding_id,
            )
            product = await conn.fetchrow(
                "SELECT sync_status, cve_count FROM products WHERE id = $1", product_id
            )

        assert final["status"] == "remediated"
        assert [h["new_status"] for h in history] == ["in_review", "remediated"]
        assert product["sync_status"] == "synced"

    async def test_cve_upsert_idempotent_across_sources(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        """
        GIVEN a CVE first inserted from CIRCL
        WHEN the same CVE is upserted from NVD (better data)
        THEN the record is updated, not duplicated
        """
        import json
        from datetime import datetime, timezone

        payload_circl = {"id": "CVE-2024-E2E-002", "summary": "CIRCL data"}
        payload_nvd = {
            "id": "CVE-2024-E2E-002",
            "published": "2024-01-01T00:00:00.000Z",
            "lastModified": "2024-01-15T00:00:00.000Z",
            "metrics": {},
            "configurations": [],
            "descriptions": [{"lang": "en", "value": "Better NVD description"}],
        }

        async with db_pool.acquire() as conn:
            now = datetime.now(tz=timezone.utc)
            # First insert: from CIRCL
            await conn.execute(
                """INSERT INTO cves (cve_id, source, raw_payload, published_at, last_modified_at)
                   VALUES ($1, 'circl', $2::jsonb, $3, $3)""",
                "CVE-2024-E2E-002", json.dumps(payload_circl), now,
            )

            # Upsert from NVD (newer last_modified_at)
            await conn.execute(
                """
                INSERT INTO cves (cve_id, source, raw_payload, published_at, last_modified_at)
                VALUES ($1, 'nvd_api', $2::jsonb, $3, NOW())
                ON CONFLICT (cve_id) DO UPDATE SET
                    raw_payload      = EXCLUDED.raw_payload,
                    source           = EXCLUDED.source,
                    last_modified_at = EXCLUDED.last_modified_at,
                    updated_at       = NOW()
                WHERE cves.last_modified_at < EXCLUDED.last_modified_at
                   OR cves.last_modified_at IS NULL
                """,
                "CVE-2024-E2E-002", json.dumps(payload_nvd), now,
            )

            count = await conn.fetchval(
                "SELECT COUNT(*) FROM cves WHERE cve_id = 'CVE-2024-E2E-002'"
            )
            row = await conn.fetchrow(
                "SELECT source FROM cves WHERE cve_id = 'CVE-2024-E2E-002'"
            )

        assert count == 1  # no duplicate
        assert row["source"] == "nvd_api"  # NVD won (newer data)
