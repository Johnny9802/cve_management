"""Contract tests for EpssClient."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from app.core.config import Settings
from app.ingestion.epss_client import EpssClient
from app.ingestion.rate_governor import TokenBucket

EPSS_BASE = "https://api.first.org/data/v1/epss"

SAMPLE_EPSS_RESPONSE = {
    "status": "OK",
    "status_code": 200,
    "version": "1.0",
    "access": "public",
    "total": 2,
    "offset": 0,
    "limit": 100,
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "1.00000", "date": "2024-01-01"},
        {"cve": "CVE-2022-0001", "epss": "0.00412", "percentile": "0.55123", "date": "2024-01-01"},
    ],
}


def _make_client() -> EpssClient:
    settings = Settings(epss_base_url=EPSS_BASE, vulncheck_api_key="")
    governor = TokenBucket(name="epss", capacity=100, refill_rate=100)
    return EpssClient(settings=settings, governor=governor)


def _make_redis(cached: dict[str, str | None] | None = None):
    """Mock Redis that returns pre-set cache values."""
    redis = AsyncMock()
    cached = cached or {}

    async def mget(*keys):
        return [cached.get(k) for k in keys]

    redis.mget = mget
    redis.pipeline = AsyncMock(return_value=AsyncMock(
        __aenter__=AsyncMock(return_value=AsyncMock(setex=AsyncMock(), execute=AsyncMock())),
        __aexit__=AsyncMock(return_value=False),
    ))
    return redis


# ------------------------------------------------------------------ #
# Parsing                                                              #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_fetch_scores_returns_correct_values() -> None:
    respx.get(EPSS_BASE).mock(return_value=httpx.Response(200, json=SAMPLE_EPSS_RESPONSE))

    client = _make_client()
    redis = _make_redis()

    result = await client.fetch_scores(["CVE-2021-44228", "CVE-2022-0001"], redis)
    await client.aclose()

    assert "CVE-2021-44228" in result
    assert result["CVE-2021-44228"].score == pytest.approx(0.97565)
    assert result["CVE-2021-44228"].percentile == pytest.approx(1.0)
    assert "CVE-2022-0001" in result


@pytest.mark.asyncio
async def test_fetch_scores_uses_cache() -> None:
    """When all CVE IDs are in cache, no HTTP call is made."""
    client = _make_client()
    cached = {
        "epss:CVE-2021-44228": json.dumps({"epss": 0.97565, "percentile": 1.0}),
    }
    redis = _make_redis(cached)

    result = await client.fetch_scores(["CVE-2021-44228"], redis)
    await client.aclose()

    assert result["CVE-2021-44228"].score == pytest.approx(0.97565)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_scores_only_fetches_uncached() -> None:
    """Only uncached CVE IDs go to the API."""
    api_response = {
        **SAMPLE_EPSS_RESPONSE,
        "data": [{"cve": "CVE-2022-0001", "epss": "0.00412", "percentile": "0.55", "date": "2024-01-01"}],
    }
    mock = respx.get(EPSS_BASE).mock(return_value=httpx.Response(200, json=api_response))

    client = _make_client()
    cached = {"epss:CVE-2021-44228": json.dumps({"epss": 0.97565, "percentile": 1.0})}
    redis = _make_redis(cached)

    await client.fetch_scores(["CVE-2021-44228", "CVE-2022-0001"], redis)
    await client.aclose()

    assert mock.called
    params = dict(mock.calls[0].request.url.params)
    assert "CVE-2022-0001" in params.get("cve", "")
    assert "CVE-2021-44228" not in params.get("cve", "")


@pytest.mark.asyncio
async def test_fetch_scores_empty_list() -> None:
    client = _make_client()
    result = await client.fetch_scores([], _make_redis())
    await client.aclose()
    assert result == {}


# ------------------------------------------------------------------ #
# Batching (> 100 CVE IDs)                                            #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_fetch_scores_batches_over_100() -> None:
    """151 CVE IDs → 2 API calls (batch 100 + batch 51)."""
    respx.get(EPSS_BASE).mock(return_value=httpx.Response(200, json={"data": []}))

    client = _make_client()
    cve_ids = [f"CVE-2024-{i:04d}" for i in range(151)]
    await client.fetch_scores(cve_ids, _make_redis())
    await client.aclose()

    assert respx.calls.call_count == 2


# ------------------------------------------------------------------ #
# Error handling                                                       #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_fetch_scores_raises_on_5xx() -> None:
    respx.get(EPSS_BASE).mock(return_value=httpx.Response(503))

    client = _make_client()
    with pytest.raises(httpx.HTTPStatusError):
        await client.fetch_scores(["CVE-2024-0001"], _make_redis())
    await client.aclose()
