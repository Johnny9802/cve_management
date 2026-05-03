"""Contract tests for CirclClient — OpSec gate and CIRCL API interaction."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from app.core.config import Settings
from app.ingestion.rate_governor import TokenBucket
from app.query.circl_client import CirclClient

CIRCL_BASE = "https://vulnerability.circl.lu/api/search"

SAMPLE_CIRCL_RESPONSE = [
    {
        "id": "CVE-2024-1234",
        "Published": "2024-01-01T00:00:00",
        "Modified": "2024-01-15T00:00:00",
        "summary": "A test vulnerability",
        "cvss": 7.5,
        "references": [],
    }
]


def _make_client() -> CirclClient:
    settings = Settings(circl_base_url=CIRCL_BASE, vulncheck_api_key="")
    governor = TokenBucket(name="circl", capacity=100, refill_rate=100)
    return CirclClient(settings=settings, governor=governor)


def _make_pool_redis(existing_cve_ids: list[str] | None = None):
    pool = MagicMock()
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=None)
    conn.executemany = AsyncMock()
    conn.execute = AsyncMock()
    conn.transaction = MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=None),
            __aexit__=AsyncMock(return_value=False),
        )
    )
    pool.acquire = MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=conn),
            __aexit__=AsyncMock(return_value=False),
        )
    )
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    return pool, redis, conn


# ─── OpSec gate ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_opsec_gate_no_cpe_skips_circl() -> None:
    """Product with no normalized CPE must never call CIRCL."""
    client = _make_client()
    pool, redis, _ = _make_pool_redis()

    result = await client.fetch_and_store(
        product_id=1,
        normalized_cpe="",        # no CPE → skip
        pool=pool,
        redis=redis,
    )
    await client.aclose()

    assert result == 0


@pytest.mark.asyncio
@respx.mock
async def test_only_cpe_vendor_product_sent_to_circl() -> None:
    """Verify that only vendor:product from CPE reaches CIRCL — not raw product name."""
    sent_path = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_path.append(request.url.path)
        return httpx.Response(200, json=[])

    respx.get(url__regex=r"https://vulnerability\.circl\.lu/api/search/.*").mock(
        side_effect=handler
    )

    client = _make_client()
    pool, redis, _ = _make_pool_redis()

    await client.fetch_and_store(
        product_id=1,
        normalized_cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        pool=pool,
        redis=redis,
    )
    await client.aclose()

    assert len(sent_path) == 1
    # Must use CPE-derived vendor/product, NOT raw strings
    assert "/nginx/nginx" in sent_path[0]


# ─── Fetch and store ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_fetch_and_store_inserts_cve_and_finding() -> None:
    respx.get(url__regex=r".*circl.*").mock(
        return_value=httpx.Response(200, json=SAMPLE_CIRCL_RESPONSE)
    )

    client = _make_client()
    pool, redis, conn = _make_pool_redis()

    result = await client.fetch_and_store(
        product_id=42,
        normalized_cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        pool=pool,
        redis=redis,
    )
    await client.aclose()

    assert result == 1
    assert conn.executemany.call_count == 2  # cves + findings


@pytest.mark.asyncio
@respx.mock
async def test_fetch_and_store_handles_404() -> None:
    respx.get(url__regex=r".*circl.*").mock(return_value=httpx.Response(404))

    client = _make_client()
    pool, redis, _ = _make_pool_redis()

    result = await client.fetch_and_store(
        product_id=1,
        normalized_cpe="cpe:2.3:a:nonexistent:nonexistent:1.0:*:*:*:*:*:*:*",
        pool=pool,
        redis=redis,
    )
    await client.aclose()
    assert result == 0


@pytest.mark.asyncio
async def test_fetch_and_store_uses_redis_cache() -> None:
    """If Redis has cached CVE IDs, CIRCL API is not called."""
    client = _make_client()
    pool, redis, conn = _make_pool_redis()
    redis.get = AsyncMock(return_value=json.dumps(["CVE-2024-1234"]))

    result = await client.fetch_and_store(
        product_id=1,
        normalized_cpe="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        pool=pool,
        redis=redis,
    )
    await client.aclose()

    # No new inserts (cache hit) but findings are linked
    assert result == 0
    conn.executemany.assert_called_once()  # only findings upsert


# ─── Severity helper ─────────────────────────────────────────────────────────

def test_circl_severity_mapping() -> None:
    from app.query.circl_client import _circl_severity
    assert _circl_severity(9.5) == "CRITICAL"
    assert _circl_severity(7.5) == "HIGH"
    assert _circl_severity(5.0) == "MEDIUM"
    assert _circl_severity(2.0) == "LOW"
    assert _circl_severity(None) is None
