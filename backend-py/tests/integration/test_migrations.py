"""Integration tests for Alembic migrations.

Requires Docker for testcontainers. Run with:
    uv run pytest tests/integration/test_migrations.py -v
"""
import pytest
import asyncpg
from testcontainers.postgres import PostgresContainer

from app.core.migrations import run_migrations


EXPECTED_TABLES = {
    "cves",
    "products",
    "cpe_resolutions",
    "findings",
    "findings_history",
    "sync_jobs",
    "sync_state",
    "subscriptions_opencve",
    "epss_history",
    "audit_log",
}

EXPECTED_GIN_INDEXES = {
    "idx_cves_raw_gin",
    "idx_cves_configurations",
    "idx_cves_metrics",
}


@pytest.fixture(scope="module")
def pg_dsn():
    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg.get_connection_url().replace("psycopg2", "asyncpg")


@pytest.mark.asyncio
async def test_migrations_create_all_tables(pg_dsn: str) -> None:
    run_migrations(pg_dsn)

    conn = await asyncpg.connect(pg_dsn)
    try:
        rows = await conn.fetch("""
            SELECT tablename FROM pg_tables
            WHERE schemaname = 'public'
        """)
        created = {r["tablename"] for r in rows}
        assert EXPECTED_TABLES.issubset(created), f"Missing tables: {EXPECTED_TABLES - created}"
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_migrations_idempotent(pg_dsn: str) -> None:
    """Running upgrade head twice must not raise."""
    run_migrations(pg_dsn)
    run_migrations(pg_dsn)  # second run should be a no-op


@pytest.mark.asyncio
async def test_gin_indexes_exist(pg_dsn: str) -> None:
    conn = await asyncpg.connect(pg_dsn)
    try:
        rows = await conn.fetch("""
            SELECT indexname FROM pg_indexes
            WHERE schemaname = 'public' AND indexname = ANY($1)
        """, list(EXPECTED_GIN_INDEXES))
        found = {r["indexname"] for r in rows}
        assert found == EXPECTED_GIN_INDEXES, f"Missing GIN indexes: {EXPECTED_GIN_INDEXES - found}"
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_sync_state_seeded(pg_dsn: str) -> None:
    conn = await asyncpg.connect(pg_dsn)
    try:
        rows = await conn.fetch("SELECT source FROM sync_state ORDER BY source")
        sources = {r["source"] for r in rows}
        assert sources == {"vulncheck", "nvd_api"}
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_cve_upsert_idempotent(pg_dsn: str) -> None:
    """ON CONFLICT (cve_id) DO UPDATE must not duplicate rows."""
    conn = await asyncpg.connect(pg_dsn)
    try:
        insert_sql = """
            INSERT INTO cves (cve_id, source, raw_payload, published_at, last_modified_at)
            VALUES ($1, 'nvd_api', '{"test": true}'::jsonb, NOW(), NOW())
            ON CONFLICT (cve_id) DO UPDATE
                SET updated_at = NOW(), raw_payload = EXCLUDED.raw_payload
        """
        await conn.execute(insert_sql, "CVE-2024-TEST-001")
        await conn.execute(insert_sql, "CVE-2024-TEST-001")  # second upsert

        count = await conn.fetchval("SELECT COUNT(*) FROM cves WHERE cve_id = $1", "CVE-2024-TEST-001")
        assert count == 1, "Upsert must not duplicate rows"
    finally:
        await conn.close()
