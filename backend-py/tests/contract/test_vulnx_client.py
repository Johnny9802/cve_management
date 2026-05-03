"""Contract tests for VulnxClient (P1) — covers parsing variants, error
handling, daily-limit cap, and OpSec enforcement."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.core.config import Settings
from app.core.http import OpsecViolationError
from app.ingestion.rate_governor import TokenBucket
from app.ingestion.vulnx_client import VulnxClient, _parse_batch_payload

VULNX_BASE = "https://cloud.projectdiscovery.io/api/v1"


def _make_client(daily_limit: int = 100, batch: int = 10, **overrides):
    settings = Settings(
        vulnx_base_url=VULNX_BASE,
        vulnx_daily_limit=daily_limit,
        vulnx_batch_size=batch,
        vulnx_api_key="test-token",
        opsec_enforcement=True,
        **overrides,
    )
    governor = TokenBucket(name="vulnx", capacity=100, refill_rate=100)
    return VulnxClient(settings=settings, governor=governor)


# ------------------------------------------------------------------ parsing


class TestPayloadParsing:
    def test_data_wrapper(self):
        body = {
            "data": [
                {
                    "cve_id": "CVE-2024-1234",
                    "poc_urls": ["https://github.com/x/exploit"],
                    "nuclei_templates": [],
                },
                {
                    "cve_id": "cve-2024-5678",
                    "poc": [],
                    "templates": ["http/cves/2024/CVE-2024-5678.yaml"],
                },
            ]
        }
        result = _parse_batch_payload(body)
        assert "CVE-2024-1234" in result
        assert result["CVE-2024-1234"].has_public_poc is True
        assert result["CVE-2024-1234"].has_nuclei_template is False
        assert "CVE-2024-5678" in result
        assert result["CVE-2024-5678"].has_nuclei_template is True

    def test_dict_keyed_by_cve(self):
        body = {
            "CVE-2024-1": {"poc_urls": ["url"]},
            "CVE-2024-2": {},
        }
        result = _parse_batch_payload(body)
        assert "CVE-2024-1" in result
        assert result["CVE-2024-1"].has_public_poc is True
        assert "CVE-2024-2" in result
        assert result["CVE-2024-2"].has_public_poc is False

    def test_list_of_objects(self):
        body = [
            {"cve": "CVE-2024-1", "exploits": [{"url": "https://x"}]},
        ]
        result = _parse_batch_payload(body)
        assert result["CVE-2024-1"].has_public_poc is True
        assert result["CVE-2024-1"].poc_urls == ["https://x"]

    def test_no_cve_id_skipped(self):
        body = [{"description": "no id at all"}]
        assert _parse_batch_payload(body) == {}


# ------------------------------------------------------------------ batching


@pytest.mark.asyncio
@respx.mock
async def test_fetch_intel_happy_path():
    respx.post(f"{VULNX_BASE}/vulnerabilities/batch").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "poc_urls": ["https://example.com/poc"],
                        "nuclei_templates": ["http/cves/2024/CVE-2024-0001.yaml"],
                    }
                ]
            },
        )
    )
    client = _make_client(batch=50)
    result = await client.fetch_intel(["cve-2024-0001"])
    await client.aclose()

    assert "CVE-2024-0001" in result
    assert result["CVE-2024-0001"].has_public_poc is True
    assert result["CVE-2024-0001"].has_nuclei_template is True


@pytest.mark.asyncio
@respx.mock
async def test_fetch_intel_batches():
    """120 CVEs with batch=50 → 3 calls."""
    respx.post(f"{VULNX_BASE}/vulnerabilities/batch").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    client = _make_client(batch=50, daily_limit=10_000)
    cve_ids = [f"CVE-2024-{i:04d}" for i in range(120)]
    await client.fetch_intel(cve_ids)
    await client.aclose()

    assert respx.calls.call_count == 3


@pytest.mark.asyncio
@respx.mock
async def test_fetch_intel_dedupes_and_uppercases():
    captured = []

    def _capture(req: httpx.Request) -> httpx.Response:
        import json
        captured.append(json.loads(req.content))
        return httpx.Response(200, json={"data": []})

    respx.post(f"{VULNX_BASE}/vulnerabilities/batch").mock(side_effect=_capture)
    client = _make_client(batch=50)
    await client.fetch_intel(["cve-2024-1", "CVE-2024-1", "CVE-2024-2"])
    await client.aclose()

    assert captured[0]["cves"] == ["CVE-2024-1", "CVE-2024-2"]


# ------------------------------------------------------------------ daily limit


@pytest.mark.asyncio
@respx.mock
async def test_daily_limit_cuts_off_processing():
    respx.post(f"{VULNX_BASE}/vulnerabilities/batch").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    client = _make_client(batch=10, daily_limit=15)
    cve_ids = [f"CVE-2024-{i:04d}" for i in range(30)]
    await client.fetch_intel(cve_ids)
    await client.aclose()

    # batch 1 → 10 used (≤15), batch 2 → would be 20 (>15) → stops
    assert client.used_today == 10
    assert respx.calls.call_count == 1


# ------------------------------------------------------------------ errors


@pytest.mark.asyncio
@respx.mock
async def test_429_does_not_raise_to_caller():
    """Rate-limit errors are caught at batch level — fetch_intel returns
    partial results rather than raising."""
    respx.post(f"{VULNX_BASE}/vulnerabilities/batch").mock(
        return_value=httpx.Response(429, json={"error": "rate limit"})
    )
    client = _make_client()
    result = await client.fetch_intel(["CVE-2024-1"])
    await client.aclose()
    assert result == {}


@pytest.mark.asyncio
@respx.mock
async def test_5xx_does_not_raise_to_caller():
    respx.post(f"{VULNX_BASE}/vulnerabilities/batch").mock(
        return_value=httpx.Response(503)
    )
    client = _make_client()
    result = await client.fetch_intel(["CVE-2024-1"])
    await client.aclose()
    assert result == {}


# ------------------------------------------------------------------ opsec


@pytest.mark.asyncio
async def test_vulnx_client_blocks_outbound_ip():
    """Confirms the VulnxClient inherits OpsecAwareClient enforcement.

    We craft a client manually and post a body containing an IP-like
    string; the wrapper must raise OpsecViolationError before any
    network call. We use the raw client.post() to bypass governor for
    speed.
    """
    client = _make_client()
    with pytest.raises(OpsecViolationError):
        await client._client.post(
            "/vulnerabilities/batch",
            json={"cves": ["CVE-2024-1"], "asset_id": "192.168.1.42"},
        )
    await client.aclose()
