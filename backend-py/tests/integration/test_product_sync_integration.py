"""Integration tests: product sync with real PostgreSQL.

Verifies the full sync_product() flow end-to-end:
- Candidate CVE discovery via CPE pattern matching
- Version range evaluation (certain/uncertain confidence)
- Finding creation and priority score computation
- Product stats update (cve_count, critical_count)
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import asyncpg
import pytest

from tests.integration.conftest import seed_cve, seed_product
from app.workers.product_sync import SyncResult, _build_search_pattern, sync_product


def _make_redis_mock() -> MagicMock:
    redis = AsyncMock()
    redis.scan_iter = AsyncMock(return_value=AsyncMock(__aiter__=lambda s: iter([])))
    return redis


@pytest.mark.asyncio
class TestProductSyncEndToEnd:
    async def test_sync_creates_finding_for_matching_cve(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        async with db_pool.acquire() as conn:
            pid = await seed_product(
                conn, name="nginx", vendor="nginx", version="1.18.0",
                normalized_cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            )
            await seed_cve(
                conn, cve_id="CVE-2024-NGINX-001", severity="HIGH", cvss_v3_score=7.5,
            )

        result = await sync_product(db_pool, _make_redis_mock(), pid)

        assert isinstance(result, SyncResult)
        assert result.product_id == pid
        assert result.candidates >= 1
        assert result.matched >= 1

        async with db_pool.acquire() as conn:
            finding = await conn.fetchrow(
                "SELECT * FROM findings WHERE product_id = $1 AND cve_id = $2",
                pid, "CVE-2024-NGINX-001",
            )
        assert finding is not None
        assert finding["status"] == "open"
        assert finding["match_confidence"] == "certain"
        assert finding["priority_score"] is not None

    async def test_sync_filters_out_of_range_version(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        """nginx 2.0.0 is OUTSIDE the affected range 1.0.0-1.20.0 → no finding."""
        async with db_pool.acquire() as conn:
            pid = await seed_product(
                conn, name="nginx", vendor="nginx", version="2.0.0",
                normalized_cpe="cpe:2.3:a:nginx:nginx:2.0.0:*:*:*:*:*:*:*",
            )
            await seed_cve(conn, cve_id="CVE-2024-NGINX-001")

        result = await sync_product(db_pool, _make_redis_mock(), pid)

        assert result.filtered >= 1

        async with db_pool.acquire() as conn:
            finding = await conn.fetchrow(
                "SELECT id FROM findings WHERE product_id = $1", pid
            )
        assert finding is None

    async def test_sync_updates_product_stats(self, db_pool: asyncpg.Pool, clean_db):
        async with db_pool.acquire() as conn:
            pid = await seed_product(
                conn, name="nginx", vendor="nginx", version="1.18.0",
                normalized_cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            )
            await seed_cve(
                conn, cve_id="CVE-2024-NGINX-001", severity="CRITICAL", cvss_v3_score=9.8
            )
            await seed_cve(
                conn, cve_id="CVE-2024-NGINX-002", severity="HIGH", cvss_v3_score=7.5
            )

        await sync_product(db_pool, _make_redis_mock(), pid)

        async with db_pool.acquire() as conn:
            product = await conn.fetchrow(
                "SELECT cve_count, critical_count, sync_status FROM products WHERE id = $1",
                pid,
            )
        assert product["sync_status"] == "synced"
        assert product["cve_count"] >= 1

    async def test_sync_is_idempotent(self, db_pool: asyncpg.Pool, clean_db):
        """Running sync_product twice must not create duplicate findings."""
        async with db_pool.acquire() as conn:
            pid = await seed_product(
                conn, name="nginx", vendor="nginx", version="1.18.0",
                normalized_cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            )
            await seed_cve(conn, cve_id="CVE-2024-NGINX-001")

        redis = _make_redis_mock()
        await sync_product(db_pool, redis, pid)
        await sync_product(db_pool, redis, pid)  # second run

        async with db_pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM findings WHERE product_id = $1", pid
            )
        assert count == 1  # no duplicate

    async def test_sync_with_no_matching_cves_is_graceful(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        async with db_pool.acquire() as conn:
            pid = await seed_product(
                conn, name="unknownapp", vendor="unknownvendor", version="99.0.0",
                normalized_cpe=None,
            )

        result = await sync_product(db_pool, _make_redis_mock(), pid)

        assert result.matched == 0
        assert result.candidates == 0

        async with db_pool.acquire() as conn:
            product = await conn.fetchrow(
                "SELECT sync_status FROM products WHERE id = $1", pid
            )
        assert product["sync_status"] == "synced"


@pytest.mark.asyncio
class TestCpePatternMatching:
    async def test_cpe_search_pattern_hits_matching_cve(
        self, db_pool: asyncpg.Pool, clean_db
    ):
        """SQL ILIKE pattern from normalized_cpe returns candidate CVEs."""
        async with db_pool.acquire() as conn:
            await seed_cve(conn, cve_id="CVE-2024-NGINX-001")

        pattern = _build_search_pattern({
            "normalized_cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            "name": "nginx", "vendor": "nginx",
        })
        assert pattern == "cpe:2.3:%:nginx:nginx:%"

        rows = await db_pool.fetch(
            """
            SELECT DISTINCT c.cve_id
            FROM cves c
            WHERE EXISTS (
                SELECT 1
                FROM jsonb_array_elements(c.raw_payload->'configurations') cfg,
                     jsonb_array_elements(cfg->'nodes') nd,
                     jsonb_array_elements(nd->'cpeMatch') m
                WHERE m->>'criteria' ILIKE $1
            )
            """,
            pattern,
        )
        cve_ids = [r["cve_id"] for r in rows]
        assert "CVE-2024-NGINX-001" in cve_ids
