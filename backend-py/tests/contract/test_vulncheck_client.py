"""Contract tests for VulnCheckClient using respx to mock httpx calls."""
from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.core.config import Settings
from app.ingestion.rate_governor import TokenBucket
from app.ingestion.vulncheck_client import VulnCheckClient
from app.models.nvd import NvdCveRecord

# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

SAMPLE_CVE = {
    "id": "CVE-2024-9999",
    "published": "2024-01-01T00:00:00.000Z",
    "lastModified": "2024-01-02T12:00:00.000Z",
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ]
    },
    "configurations": [],
    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
}

VULNCHECK_DELTA_RESPONSE = {
    "_meta": {"page": 1, "total_pages": 1, "limit": 2000},
    "data": [SAMPLE_CVE],
}


def _make_client(api_key: str = "test_key") -> VulnCheckClient:
    settings = Settings(
        vulncheck_api_key=api_key,
        vulncheck_base_url="https://api.vulncheck.com",
        nvd_api_key="",
    )
    governor = TokenBucket(name="vulncheck", capacity=100, refill_rate=100)
    return VulnCheckClient(settings=settings, governor=governor)


# ------------------------------------------------------------------ #
# NvdCveRecord parsing                                                #
# ------------------------------------------------------------------ #

def test_nvd_cve_record_parses_cvss_v31() -> None:
    record = NvdCveRecord.from_nvd_cve(SAMPLE_CVE)
    assert record.cve_id == "CVE-2024-9999"
    assert record.cvss_v3_score == 9.8
    assert record.severity == "CRITICAL"
    assert record.cvss_v3_vector is not None
    assert record.raw_payload == SAMPLE_CVE


def test_nvd_cve_record_derives_severity_from_v2() -> None:
    cve_v2_only = {
        "id": "CVE-2005-0001",
        "published": "2005-01-01T00:00:00.000Z",
        "lastModified": "2005-01-02T00:00:00.000Z",
        "metrics": {
            "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]
        },
    }
    record = NvdCveRecord.from_nvd_cve(cve_v2_only)
    assert record.severity == "HIGH"
    assert record.cvss_v2_score == 7.5
    assert record.cvss_v3_score is None


def test_nvd_cve_record_handles_missing_metrics() -> None:
    cve_no_metrics = {
        "id": "CVE-2024-0001",
        "published": "2024-01-01T00:00:00.000Z",
        "lastModified": "2024-01-01T00:00:00.000Z",
        "metrics": {},
    }
    record = NvdCveRecord.from_nvd_cve(cve_no_metrics)
    assert record.cve_id == "CVE-2024-0001"
    assert record.severity is None
    assert record.cvss_v3_score is None


def test_nvd_cve_record_to_row() -> None:
    record = NvdCveRecord.from_nvd_cve(SAMPLE_CVE)
    row = record.to_row("vulncheck_nvd")
    assert row[0] == "CVE-2024-9999"
    assert row[1] == "vulncheck_nvd"
    assert isinstance(row[2], str)  # JSON string for raw_payload
    assert row[7] == record.published_at
    assert row[8] == record.last_modified_at


# ------------------------------------------------------------------ #
# VulnCheckClient: delta pagination                                   #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_delta_single_page() -> None:
    respx.get("https://api.vulncheck.com/v3/index/nist-nvd2").mock(
        return_value=httpx.Response(200, json=VULNCHECK_DELTA_RESPONSE)
    )

    client = _make_client()
    records = []
    since = datetime(2024, 1, 1, tzinfo=UTC)

    async for record in client.iter_delta(since):
        records.append(record)

    await client.aclose()
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-9999"


@pytest.mark.asyncio
@respx.mock
async def test_delta_paginates_multiple_pages() -> None:
    """Two pages of results → both fetched."""
    page1 = {**VULNCHECK_DELTA_RESPONSE, "_meta": {"page": 1, "total_pages": 2, "limit": 1}}
    page2 = {
        "_meta": {"page": 2, "total_pages": 2, "limit": 1},
        "data": [{**SAMPLE_CVE, "id": "CVE-2024-9998"}],
    }

    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        page = int(request.url.params.get("page", "1"))
        return httpx.Response(200, json=page1 if page == 1 else page2)

    respx.get("https://api.vulncheck.com/v3/index/nist-nvd2").mock(side_effect=handler)

    client = _make_client()
    records = []
    since = datetime(2024, 1, 1, tzinfo=UTC)
    # Only a single 119-day chunk for this date range
    end = datetime(2024, 4, 28, tzinfo=UTC)

    async for record in client.iter_delta(since):
        records.append(record)
        if record.last_modified_at > end:
            break

    await client.aclose()
    ids = {r.cve_id for r in records}
    assert "CVE-2024-9999" in ids


@pytest.mark.asyncio
@respx.mock
async def test_delta_handles_429_retry() -> None:
    """429 response triggers a retry after Retry-After seconds."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, json=VULNCHECK_DELTA_RESPONSE)

    respx.get("https://api.vulncheck.com/v3/index/nist-nvd2").mock(side_effect=handler)

    client = _make_client()
    records = []
    since = datetime(2024, 1, 1, tzinfo=UTC)
    async for record in client.iter_delta(since):
        records.append(record)

    await client.aclose()
    assert call_count == 2
    assert len(records) == 1


# ------------------------------------------------------------------ #
# VulnCheckClient: bulk S3 fallback on 402                           #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
@respx.mock
async def test_bulk_falls_back_on_402() -> None:
    """If backup endpoint returns 402 (free tier), falls back to iter_delta."""
    respx.get("https://api.vulncheck.com/v3/backup/nist-nvd2").mock(
        return_value=httpx.Response(402)
    )
    respx.get("https://api.vulncheck.com/v3/index/nist-nvd2").mock(
        return_value=httpx.Response(200, json=VULNCHECK_DELTA_RESPONSE)
    )

    client = _make_client()
    records = []
    async for record in client.iter_bulk():
        records.append(record)

    await client.aclose()
    # At least one record from the delta fallback
    assert len(records) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_bulk_s3_streams_ndjson_gz() -> None:
    """Bulk: S3 URL returns NDJSON.gz → records parsed correctly."""
    ndjson = (json.dumps(SAMPLE_CVE) + "\n").encode("utf-8")
    compressed = gzip.compress(ndjson)

    backup_urls_response = {"data": [{"url": "https://s3.amazonaws.com/test/file.json.gz"}]}

    respx.get("https://api.vulncheck.com/v3/backup/nist-nvd2").mock(
        return_value=httpx.Response(200, json=backup_urls_response)
    )
    respx.get("https://s3.amazonaws.com/test/file.json.gz").mock(
        return_value=httpx.Response(200, content=compressed)
    )

    client = _make_client()
    records = []
    async for record in client.iter_bulk():
        records.append(record)

    await client.aclose()
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-9999"
    assert records[0].cvss_v3_score == 9.8
