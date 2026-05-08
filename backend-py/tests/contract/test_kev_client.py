"""Contract tests for KevClient."""
from __future__ import annotations

import json
from datetime import date
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from app.core.config import Settings
from app.ingestion.kev_client import _CACHE_KEY, KevClient
from app.ingestion.rate_governor import TokenBucket

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SAMPLE_KEV = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.01.01",
    "dateReleased": "2024-01-01T00:00:00Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "shortDescription": "...",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
        },
        {
            "cveID": "CVE-2022-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget RCE",
            "dateAdded": "2022-01-15",
            "shortDescription": "...",
            "requiredAction": "Apply updates",
            "dueDate": "2022-02-01",
        },
    ],
}


def _make_client() -> KevClient:
    settings = Settings(cisa_kev_url=KEV_URL, vulncheck_api_key="")
    governor = TokenBucket(name="kev", capacity=10, refill_rate=10)
    return KevClient(settings=settings, governor=governor)


def _make_redis(cached_value: str | None = None) -> AsyncMock:
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=cached_value)
    redis.setex = AsyncMock()
    return redis


# ------------------------------------------------------------------ #
# Fetching                                                             #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_get_catalog_fetches_from_cisa() -> None:
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=SAMPLE_KEV))

    client = _make_client()
    catalog = await client.get_catalog(_make_redis())
    await client.aclose()

    assert "CVE-2021-44228" in catalog
    assert catalog["CVE-2021-44228"] == date(2021, 12, 10)
    assert "CVE-2022-0001" in catalog
    assert catalog["CVE-2022-0001"] == date(2022, 1, 15)


@pytest.mark.asyncio
async def test_get_catalog_uses_redis_cache() -> None:
    cached = json.dumps({"CVE-2021-44228": "2021-12-10"})
    redis = _make_redis(cached_value=cached)

    client = _make_client()
    catalog = await client.get_catalog(redis)
    await client.aclose()

    assert catalog["CVE-2021-44228"] == date(2021, 12, 10)
    redis.get.assert_called_once_with(_CACHE_KEY)


@pytest.mark.asyncio
@respx.mock
async def test_get_catalog_skips_bad_dates() -> None:
    kev = {
        **SAMPLE_KEV,
        "vulnerabilities": [
            {**SAMPLE_KEV["vulnerabilities"][0]},
            {
                "cveID": "CVE-2023-9999",
                "dateAdded": "not-a-date",
                "vendorProject": "X",
                "product": "Y",
                "vulnerabilityName": "Z",
                "shortDescription": "",
                "requiredAction": "",
                "dueDate": "",
            },
        ],
    }
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=kev))

    client = _make_client()
    catalog = await client.get_catalog(_make_redis())
    await client.aclose()

    assert "CVE-2021-44228" in catalog
    assert "CVE-2023-9999" not in catalog


@pytest.mark.asyncio
@respx.mock
async def test_get_catalog_caches_after_fetch() -> None:
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=SAMPLE_KEV))
    redis = _make_redis()

    client = _make_client()
    await client.get_catalog(redis)
    await client.aclose()

    redis.setex.assert_called_once()
    key, ttl, value = redis.setex.call_args[0]
    assert key == _CACHE_KEY
    assert ttl == 6 * 3600
    parsed = json.loads(value)
    assert "CVE-2021-44228" in parsed


@pytest.mark.asyncio
@respx.mock
async def test_get_catalog_raises_on_network_error() -> None:
    respx.get(KEV_URL).mock(side_effect=httpx.ConnectError("timeout"))

    client = _make_client()
    with pytest.raises(httpx.ConnectError):
        await client.get_catalog(_make_redis())
    await client.aclose()
