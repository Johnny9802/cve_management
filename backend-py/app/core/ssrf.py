"""SSRF protection for user-supplied URLs (P7).

Webhooks accept a destination URL from the user. We must prevent that URL
from pointing at internal infrastructure:

* Loopback           — 127.0.0.0/8, ::1
* Link-local         — 169.254.0.0/16
* Private IPv4 (RFC1918) — 10/8, 172.16/12, 192.168/16
* IPv6 ULA / link-local
* Cloud metadata     — 169.254.169.254 (also covered by link-local)
* Multicast          — 224/4
* Unspecified        — 0.0.0.0, ::
* Reserved           — 240/4

If the URL hostname resolves to *any* IP in the blocklist, the request
is rejected. An optional allowlist (``WEBHOOK_HOST_ALLOWLIST``) overrides
the block on a per-host basis (e.g. for self-hosted Slack receivers
inside a controlled VPC).

DNS rebinding mitigation: callers should resolve the hostname once and
connect by IP, otherwise an attacker can pass the validate step and serve
a different IP at request time. The function used by the webhook worker
returns the resolved address along with the success flag so the caller
can pin the connection.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


_PRIVATE_IPV4_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("0.0.0.0/8"),       # unspecified / "this network"
    ipaddress.IPv4Network("10.0.0.0/8"),      # RFC1918
    ipaddress.IPv4Network("100.64.0.0/10"),   # CGNAT
    ipaddress.IPv4Network("127.0.0.0/8"),     # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.IPv4Network("172.16.0.0/12"),   # RFC1918
    ipaddress.IPv4Network("192.0.0.0/24"),    # IETF protocol assignments
    ipaddress.IPv4Network("192.168.0.0/16"),  # RFC1918
    ipaddress.IPv4Network("198.18.0.0/15"),   # benchmarking
    ipaddress.IPv4Network("224.0.0.0/4"),     # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),     # reserved
)

_PRIVATE_IPV6_NETS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),     # unique-local
    ipaddress.IPv6Network("fe80::/10"),    # link-local
    ipaddress.IPv6Network("ff00::/8"),     # multicast
    ipaddress.IPv6Network("::/128"),       # unspecified
)


@dataclass(frozen=True, slots=True)
class SsrfCheckResult:
    allowed: bool
    reason: str | None
    resolved_ips: tuple[str, ...]


class SsrfBlockedError(ValueError):
    """Raised when a URL fails the SSRF guard."""


def _is_private(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in _PRIVATE_IPV4_NETS)
    if isinstance(ip, ipaddress.IPv6Address):
        return any(ip in net for net in _PRIVATE_IPV6_NETS)
    return True  # unknown family → fail closed


def _allowlist_set(raw: str | None) -> frozenset[str]:
    if not raw:
        return frozenset()
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def check_url(
    url: str,
    *,
    allowlist: str | Iterable[str] | None = None,
    require_https: bool = False,
) -> SsrfCheckResult:
    """Validate ``url`` against the SSRF block list.

    Parameters
    ----------
    url : str
        The webhook destination supplied by the user.
    allowlist : str | iterable[str] | None
        Comma-separated string (env-var style) or iterable of hostnames
        that are exempt from the block list. Useful for CI / self-hosted
        receivers reachable only via private IPs.
    require_https : bool
        If True, ``http://`` is rejected.

    Returns
    -------
    SsrfCheckResult
        ``allowed=True`` means the URL is safe to dispatch. Resolved IPs
        are returned so the caller can pin the outbound connection (DNS
        rebinding mitigation).
    """
    if isinstance(allowlist, str) or allowlist is None:
        allow = _allowlist_set(allowlist if isinstance(allowlist, str) else None)
    else:
        allow = frozenset(h.lower() for h in allowlist)

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return SsrfCheckResult(False, f"scheme_not_allowed:{parsed.scheme}", ())
    if require_https and parsed.scheme != "https":
        return SsrfCheckResult(False, "https_required", ())
    host = parsed.hostname
    if not host:
        return SsrfCheckResult(False, "missing_hostname", ())

    host_l = host.lower()
    if host_l in allow:
        # Even allowlisted hosts must resolve — return their IPs so the
        # caller can use them, but we do not block private IPs here.
        try:
            infos = socket.getaddrinfo(host, None)
            ips = tuple({info[4][0] for info in infos})
        except OSError:
            return SsrfCheckResult(False, "dns_resolution_failed", ())
        return SsrfCheckResult(True, None, ips)

    # Block obviously-internal hostnames before resolution
    if host_l in {"localhost", "ip6-localhost"}:
        return SsrfCheckResult(False, "loopback_hostname", ())

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        return SsrfCheckResult(False, f"dns_resolution_failed:{exc}", ())

    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            return SsrfCheckResult(False, f"invalid_ip:{addr}", tuple(ips))
        if _is_private(ip_obj):
            return SsrfCheckResult(False, f"private_ip:{addr}", tuple(ips))
        ips.append(str(ip_obj))
    return SsrfCheckResult(True, None, tuple(ips))


def assert_url_allowed(
    url: str,
    *,
    allowlist: str | Iterable[str] | None = None,
    require_https: bool = False,
) -> SsrfCheckResult:
    """Raise ``SsrfBlockedError`` if the URL fails the guard."""
    result = check_url(url, allowlist=allowlist, require_https=require_https)
    if not result.allowed:
        raise SsrfBlockedError(result.reason or "ssrf_blocked")
    return result
