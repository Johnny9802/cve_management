"""SSRF guard tests (P7) — assert that user-supplied webhook URLs cannot
target internal infrastructure unless explicitly allow-listed."""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from app.core.ssrf import SsrfBlockedError, assert_url_allowed, check_url


def _resolve(addr: str):
    """getaddrinfo result: (family, type, proto, canonname, sockaddr)."""
    return [(socket.AF_INET, 0, 0, "", (addr, 0))]


# ──────────────────────────────────────────────────── public addresses


class TestPublicAllowed:
    def test_public_https(self):
        with patch("app.core.ssrf.socket.getaddrinfo", return_value=_resolve("93.184.216.34")):
            r = check_url("https://example.com/hook")
        assert r.allowed is True
        assert "93.184.216.34" in r.resolved_ips


# ───────────────────────────────────────────────── private/loopback


class TestPrivateBlocked:
    @pytest.mark.parametrize("addr", [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",       # CGNAT
        "224.0.0.1",        # multicast
    ])
    def test_blocks_private_ipv4(self, addr):
        with patch("app.core.ssrf.socket.getaddrinfo", return_value=_resolve(addr)):
            r = check_url("https://attacker-controlled.example/whatever")
        assert r.allowed is False
        assert r.reason and r.reason.startswith("private_ip:")

    def test_blocks_localhost_hostname(self):
        r = check_url("http://localhost:8080/abuse")
        assert r.allowed is False
        assert r.reason == "loopback_hostname"

    def test_blocks_unknown_scheme(self):
        r = check_url("file:///etc/passwd")
        assert r.allowed is False
        assert r.reason and r.reason.startswith("scheme_not_allowed:")

    def test_blocks_missing_host(self):
        r = check_url("http:///")
        assert r.allowed is False
        assert r.reason == "missing_hostname"


# ───────────────────────────────────────────────────── allowlist


class TestAllowlist:
    def test_allowlist_overrides_private_block(self):
        with patch("app.core.ssrf.socket.getaddrinfo", return_value=_resolve("10.0.5.5")):
            r = check_url(
                "https://internal-slack.example.lan/hook",
                allowlist="internal-slack.example.lan",
            )
        # Allowed because hostname matches the allowlist (we still resolve
        # to surface the IPs to the caller).
        assert r.allowed is True
        assert "10.0.5.5" in r.resolved_ips


# ──────────────────────────────────────────────────────── helper


class TestAssertHelper:
    def test_assert_raises_on_block(self):
        with pytest.raises(SsrfBlockedError):
            assert_url_allowed("http://localhost/x")

    def test_assert_returns_result_when_allowed(self):
        with patch("app.core.ssrf.socket.getaddrinfo", return_value=_resolve("93.184.216.34")):
            r = assert_url_allowed("https://example.com/x")
        assert r.allowed is True


# ───────────────────────────────────────────── require_https


class TestHttpsOnly:
    def test_blocks_http_when_required(self):
        with patch("app.core.ssrf.socket.getaddrinfo", return_value=_resolve("93.184.216.34")):
            r = check_url("http://example.com/hook", require_https=True)
        assert r.allowed is False
        assert r.reason == "https_required"
