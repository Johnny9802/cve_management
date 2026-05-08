"""Contract tests for NvdClient using respx to mock httpx calls."""
from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.core.config import Settings
from app.ingestion.nvd_client import NvdClient, _fmt_date
from app.ingestion.rate_governor import TokenBucket

# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SAMPLE_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "published": "2024-01-01T00:00:00.000Z",
                "lastModified": "2024-01-15T12:00:00.000Z",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        }
                    ]
                },
            }
        }
    ],
}

EMPTY_NVD_RESPONSE = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": [],
}


def _make_client(api_key: str = "") -> NvdClient:
    settings = Settings(
        nvd_base_url=NVD_BASE,
        nvd_api_key=api_key,
        nvd_request_delay_ms=0,  # no sleep in tests
        nvd_request_delay_key_ms=0,
        vulncheck_api_key="",
    )
    governor = TokenBucket(name="nvd", capacity=100, refill_rate=100)
    return NvdClient(settings=settings, governor=governor)


# ------------------------------------------------------------------ #
# Date format                                                          #
# ------------------------------------------------------------------ #

def test_fmt_date_format() -> None:
    dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
    result = _fmt_date(dt)
    assert result == "2024-01-15T10:30:00.000 UTC+00:00"


# ------------------------------------------------------------------ #
# Basic fetch                                                          #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_iter_delta_single_page() -> None:
    respx.get(NVD_BASE).mock(return_value=httpx.Response(200, json=SAMPLE_NVD_RESPONSE))

    client = _make_client()
    records = []
    since = datetime(2024, 1, 1, tzinfo=UTC)
    async for record in client.iter_delta(since):
        records.append(record)

    await client.aclose()
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-1234"
    assert records[0].cvss_v3_score == 7.5
    assert records[0].severity == "HIGH"


@pytest.mark.asyncio
@respx.mock
async def test_iter_delta_empty_response() -> None:
    respx.get(NVD_BASE).mock(return_value=httpx.Response(200, json=EMPTY_NVD_RESPONSE))

    client = _make_client()
    records = []
    since = datetime(2024, 1, 1, tzinfo=UTC)
    async for record in client.iter_delta(since):
        records.append(record)

    await client.aclose()
    assert records == []


# ------------------------------------------------------------------ #
# Pagination                                                           #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_iter_delta_paginates() -> None:
    """When totalResults > resultsPerPage, multiple requests are made."""
    page1 = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 2,
        "vulnerabilities": [SAMPLE_NVD_RESPONSE["vulnerabilities"][0]],
    }
    page2 = {
        "resultsPerPage": 1,
        "startIndex": 1,
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    **SAMPLE_NVD_RESPONSE["vulnerabilities"][0]["cve"],
                    "id": "CVE-2024-5678",
                }
            }
        ],
    }

    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        start = int(request.url.params.get("startIndex", "0"))
        return httpx.Response(200, json=page1 if start == 0 else page2)

    respx.get(NVD_BASE).mock(side_effect=handler)

    client = _make_client()
    records = []
    since = datetime(2024, 1, 1, tzinfo=UTC)
    async for record in client.iter_delta(since):
        records.append(record)

    await client.aclose()
    assert call_count == 2
    assert {r.cve_id for r in records} == {"CVE-2024-1234", "CVE-2024-5678"}


# ------------------------------------------------------------------ #
# 429 handling                                                         #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_iter_delta_retries_on_429() -> None:
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, json=SAMPLE_NVD_RESPONSE)

    respx.get(NVD_BASE).mock(side_effect=handler)

    client = _make_client()
    records = []
    since = datetime(2024, 1, 1, tzinfo=UTC)
    async for record in client.iter_delta(since):
        records.append(record)

    await client.aclose()
    assert call_count == 2
    assert len(records) == 1


# ------------------------------------------------------------------ #
# Date range chunking (120-day constraint)                             #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_iter_delta_chunks_large_range() -> None:
    """A 300-day range produces at least 3 API calls (3 × 119-day chunks)."""
    respx.get(NVD_BASE).mock(return_value=httpx.Response(200, json=EMPTY_NVD_RESPONSE))

    client = _make_client()
    since = datetime(2023, 1, 1, tzinfo=UTC)
    # force end to be ~300 days from since — achieved by using a fixed "now" indirectly
    # The client uses datetime.now() internally; as long as since is 300+ days ago this fires ≥3 chunks
    async for _ in client.iter_delta(since):
        pass

    await client.aclose()
    assert respx.calls.call_count >= 3, (
        f"Expected ≥3 chunked calls for 300-day range, got {respx.calls.call_count}"
    )


# ------------------------------------------------------------------ #
# apiKey header                                                        #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_api_key_sent_as_header() -> None:
    sent_headers: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent_headers.update(dict(request.headers))
        return httpx.Response(200, json=EMPTY_NVD_RESPONSE)

    respx.get(NVD_BASE).mock(side_effect=handler)

    client = _make_client(api_key="test-nvd-key-123")
    since = datetime(2024, 1, 1, tzinfo=UTC)
    async for _ in client.iter_delta(since):
        pass

    await client.aclose()
    assert sent_headers.get("apikey") == "test-nvd-key-123"
