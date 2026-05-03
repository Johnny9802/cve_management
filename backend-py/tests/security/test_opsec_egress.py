"""OpSec security tests (P10) — verify that ``OpsecAwareClient`` blocks
asset-like data in outbound bodies.

The tests run *without* hitting the network: they construct an
``OpsecAwareClient`` pointed at an httpx mock transport. If a request
ever reaches the transport, the test fails (because the wrapper should
have blocked it).
"""
from __future__ import annotations

import httpx
import pytest

from app.core.http import OpsecAwareClient, OpsecViolationError


def _client(enforcement: bool = True) -> OpsecAwareClient:
    # Real transport never gets called when enforcement blocks, but
    # we still wire one for safety.
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, json={"ok": True})
    )
    return OpsecAwareClient(
        provider="test",
        enforcement=enforcement,
        transport=transport,
        base_url="https://example.test",
    )


# ------------------------------------------------------------------ block


class TestBlockedPayloads:
    @pytest.mark.asyncio
    async def test_blocks_ipv4_in_json(self):
        async with _client() as c:
            with pytest.raises(OpsecViolationError) as exc:
                await c.post("/x", json={"target": "192.168.1.42"})
        assert exc.value.reason == "ipv4"
        assert exc.value.provider == "test"

    @pytest.mark.asyncio
    async def test_blocks_mac_in_json(self):
        async with _client() as c:
            with pytest.raises(OpsecViolationError) as exc:
                await c.post("/x", json={"mac": "aa:bb:cc:dd:ee:ff"})
        assert exc.value.reason == "mac"

    @pytest.mark.asyncio
    async def test_blocks_hostname_field_name(self):
        async with _client() as c:
            with pytest.raises(OpsecViolationError) as exc:
                await c.post("/x", json={"hostname": "host01"})
        assert exc.value.reason == "asset_field_name"

    @pytest.mark.asyncio
    async def test_blocks_asset_id_field_name(self):
        async with _client() as c:
            with pytest.raises(OpsecViolationError) as exc:
                await c.post("/x", json={"asset_id": "abc-001"})
        assert exc.value.reason == "asset_field_name"

    @pytest.mark.asyncio
    async def test_blocks_in_content_bytes(self):
        async with _client() as c:
            body = b'{"machine_id": "fingerprint-xyz"}'
            with pytest.raises(OpsecViolationError):
                await c.post("/x", content=body)


# ------------------------------------------------------------------ allow


class TestAllowedPayloads:
    @pytest.mark.asyncio
    async def test_cve_id_only_allowed(self):
        async with _client() as c:
            resp = await c.post("/x", json={"cves": ["CVE-2024-1234"]})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_cpe_with_version_allowed(self):
        # CPE strings contain numeric tokens but no IPv4 octet pattern,
        # so they must pass.
        cpe = "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
        async with _client() as c:
            resp = await c.post("/x", json={"cpe": cpe})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_request_with_no_body_allowed(self):
        async with _client() as c:
            resp = await c.get("/x")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_url_with_ip_allowed(self):
        # URL/path are NOT scanned (CPE tokens collide with IP regex).
        async with _client() as c:
            resp = await c.get("/cpe/cpe:2.3:a:foo:bar:1.0.0")
        assert resp.status_code == 200


# ------------------------------------------------------------------ dry-run


class TestDryRunMode:
    @pytest.mark.asyncio
    async def test_enforcement_off_logs_but_does_not_raise(self):
        async with _client(enforcement=False) as c:
            # Should not raise, request goes through to mock transport.
            resp = await c.post("/x", json={"hostname": "host01"})
        assert resp.status_code == 200


# ------------------------------------------------------------------ metrics


class TestMetricsHook:
    @pytest.mark.asyncio
    async def test_metrics_record_egress_block_called(self):
        captured: list[tuple[str, str]] = []

        class _Sink:
            def record_egress_block(self, provider: str, reason: str) -> None:
                captured.append((provider, reason))

        async with _client() as c:
            c.attach_metrics(_Sink())
            with pytest.raises(OpsecViolationError):
                await c.post("/x", json={"hostname": "h"})

        assert captured == [("test", "asset_field_name")]
