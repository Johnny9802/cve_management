"""Session-scoped testcontainers fixtures for integration tests.

Containers start once per pytest session to minimise overhead.
Each test cleans up its own data to remain independent.

Requirements:
  - Docker daemon running
  - uv run pytest tests/integration/ -v
"""
from __future__ import annotations

import asyncio

import asyncpg
import pytest
import pytest_asyncio
from redis.asyncio import Redis
from testcontainers.postgres import PostgresContainer

try:
    from testcontainers.redis import RedisContainer
    _HAS_REDIS_CONTAINER = True
except ImportError:
    _HAS_REDIS_CONTAINER = False


# ── Event loop (session-scoped for all async fixtures) ────────────────────────

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Containers (session-scoped — start once) ──────────────────────────────────

@pytest.fixture(scope="session")
def pg_container():
    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg


@pytest.fixture(scope="session")
def redis_container():
    if not _HAS_REDIS_CONTAINER:
        pytest.skip("testcontainers[redis] not installed")
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


# ── Database pool (session-scoped) ────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session")
async def db_pool(pg_container: PostgresContainer) -> asyncpg.Pool:
    dsn = pg_container.get_connection_url()
    # Remove SQLAlchemy driver suffix — asyncpg uses plain postgresql://
    dsn = dsn.replace("+psycopg2", "")

    # Run migrations in a thread (Alembic uses asyncio.run internally)
    from app.core.migrations import run_migrations
    await asyncio.to_thread(run_migrations, dsn)

    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
    yield pool  # type: ignore[misc]
    await pool.close()


@pytest_asyncio.fixture(scope="session")
async def redis_client(redis_container) -> Redis:
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    client: Redis = Redis(host=host, port=int(port), decode_responses=True)
    yield client
    await client.aclose()


# ── Per-test cleanup ──────────────────────────────────────────────────────────

_TRUNCATE_SQL = """
TRUNCATE TABLE
    audit_log,
    epss_history,
    subscriptions_opencve,
    findings_history,
    findings,
    sync_jobs,
    products,
    cpe_resolutions,
    cves,
    users
RESTART IDENTITY CASCADE
"""


@pytest_asyncio.fixture(autouse=False)
async def clean_db(db_pool: asyncpg.Pool):
    """Truncate all application tables after each test that uses this fixture."""
    yield
    await db_pool.execute(_TRUNCATE_SQL)


# ── Seed helpers ──────────────────────────────────────────────────────────────

async def seed_product(
    conn: asyncpg.Connection,
    name: str = "nginx",
    vendor: str = "nginx",
    version: str = "1.18.0",
    normalized_cpe: str | None = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
) -> int:
    row = await conn.fetchrow(
        """
        INSERT INTO products (name, vendor, version, normalized_cpe)
        VALUES ($1, $2, $3, $4) RETURNING id
        """,
        name, vendor, version, normalized_cpe,
    )
    return row["id"]


async def seed_cve(
    conn: asyncpg.Connection,
    cve_id: str = "CVE-2024-TEST-001",
    severity: str = "HIGH",
    cvss_v3_score: float = 7.5,
    is_kev: bool = False,
    raw_payload: dict | None = None,
) -> str:
    import json
    payload = raw_payload or {
        "id": cve_id,
        "published": "2024-01-01T00:00:00.000Z",
        "lastModified": "2024-01-15T00:00:00.000Z",
        "metrics": {
            "cvssMetricV31": [{"cvssData": {
                "baseScore": cvss_v3_score,
                "baseSeverity": severity,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            }}]
        },
        "configurations": [
            {"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.0",
                 "versionEndExcluding": "1.20.0"}
            ]}]}
        ],
        "descriptions": [{"lang": "en", "value": f"Test vulnerability {cve_id}"}],
    }
    await conn.execute(
        """
        INSERT INTO cves (cve_id, source, raw_payload, cvss_v3_score, severity,
                          is_kev, published_at, last_modified_at)
        VALUES ($1, 'nvd_api', $2::jsonb, $3, $4, $5, NOW(), NOW())
        ON CONFLICT (cve_id) DO NOTHING
        """,
        cve_id, json.dumps(payload), cvss_v3_score, severity, is_kev,
    )
    return cve_id


async def seed_finding(
    conn: asyncpg.Connection,
    product_id: int,
    cve_id: str,
    status: str = "open",
    priority_score: float = 50.0,
) -> int:
    row = await conn.fetchrow(
        """
        INSERT INTO findings (product_id, cve_id, status, match_confidence, priority_score)
        VALUES ($1, $2, $3, 'certain', $4) RETURNING id
        """,
        product_id, cve_id, status, priority_score,
    )
    return row["id"]
