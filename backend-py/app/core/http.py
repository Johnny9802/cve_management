"""OpSec-aware HTTP client (P10).

A thin ``httpx.AsyncClient`` subclass that scans request bodies for tokens
that look like asset-inventory data (IPv4 addresses, MAC addresses, common
field names such as ``hostname`` / ``asset_id`` / ``asset_tag``) and refuses
to send them outbound.

Why a wrapper?
--------------
The platform's OpSec rule is "asset inventory MUST NOT leave the perimeter
for routine queries". Today this is enforced *implicitly* by callers
(everyone knows you only send CVE IDs / vendor / product / CPE to external
providers). With the addition of vulnx (P1), webhooks (P7) and future
integrations the surface area widens. A central wrapper turns the rule into
*explicit* enforcement, with an audit log entry every time a request is
blocked.

Behaviour
---------
- ``request()`` inspects ``json``, ``content`` and ``data`` kwargs.
- If a body contains an asset-like pattern, the request is dropped:
  * ``opsec.egress_blocked`` is logged with ``url`` (host only), ``reason``,
    ``provider`` (caller-tagged on instance creation) and ``redacted_sample``
    (a 32-byte hash of the offending substring — never the body itself).
  * Metrics are incremented if a registry is attached.
  * ``OpsecViolationError`` is raised, unless
    ``settings.opsec_enforcement=False`` (dry-run mode for staging).
- URL/query/path are *not* scanned, because legitimate CPEs and CVE IDs
  contain numeric tokens that would trigger the IP regex (e.g.
  ``cpe:2.3:a:openssl:openssl:1.1.1``).

Allowed senders
---------------
Each ``OpsecAwareClient`` is instantiated with a ``provider`` tag and an
``allow_ip_in_body`` flag. The flag is reserved for clients whose protocol
*requires* sending an IP (none today; default ``False``).

OpSec is fail-closed by default: enforcement is on unless explicitly
disabled in config.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)


# Patterns that indicate an asset-like leak. Each pattern is a (name, regex)
# tuple so the audit log entry can identify the violated rule.
_BLOCKLIST: list[tuple[str, re.Pattern[str]]] = [
    (
        "ipv4",
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b"
        ),
    ),
    (
        "mac",
        re.compile(r"\b[0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(?:\1[0-9a-fA-F]{2}){4}\b"),
    ),
    # Field-name signals: JSON keys that strongly suggest inventory data.
    (
        "asset_field_name",
        re.compile(
            r'"(hostname|host|asset_id|asset_tag|asset_uuid|machine_id|'
            r'mac_address|ip_address|ipv4|ipv6|fqdn)"\s*:',
            re.IGNORECASE,
        ),
    ),
]


class OpsecViolationError(RuntimeError):
    """Raised when an outbound request body contains asset-like data."""

    def __init__(self, provider: str, reason: str) -> None:
        super().__init__(f"OpSec violation in provider={provider}: {reason}")
        self.provider = provider
        self.reason = reason


class OpsecAwareClient(httpx.AsyncClient):
    """``httpx.AsyncClient`` with outbound-body asset-data enforcement.

    Parameters
    ----------
    provider : str
        Stable identifier of the caller (e.g. ``"vulnx"``, ``"webhook"``).
        Goes into log entries and metric labels.
    enforcement : bool, default True
        When False, violations are logged but the request proceeds. Useful
        for staging rollouts.
    metrics : object | None
        Optional metrics sink with ``record_egress_block(provider, reason)``
        method. The MetricsRegistry exposes such hook (see
        ``app/core/metrics.py`` extension below).
    """

    def __init__(
        self,
        *args: Any,
        provider: str,
        enforcement: bool = True,
        metrics: Any | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._provider = provider
        self._enforcement = enforcement
        self._metrics = metrics

    @property
    def provider(self) -> str:
        return self._provider

    def attach_metrics(self, metrics: Any) -> None:
        self._metrics = metrics

    async def request(self, method: str, url: Any, **kwargs: Any) -> httpx.Response:  # type: ignore[override]
        body_str = self._body_as_string(kwargs)
        if body_str:
            violation = self._scan(body_str)
            if violation:
                rule, sample_hash = violation
                self._on_violation(method, url, rule, sample_hash)
                if self._enforcement:
                    raise OpsecViolationError(self._provider, rule)
        return await super().request(method, url, **kwargs)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _body_as_string(kwargs: dict[str, Any]) -> str | None:
        """Return a string representation of any body kwarg, or None."""
        if (data := kwargs.get("json")) is not None:
            try:
                return json.dumps(data, default=str)
            except (TypeError, ValueError):
                return str(data)
        if (data := kwargs.get("content")) is not None:
            if isinstance(data, (bytes, bytearray)):
                try:
                    return data.decode("utf-8", errors="replace")
                except Exception:  # pragma: no cover — defensive
                    return None
            return str(data)
        if (data := kwargs.get("data")) is not None:
            return str(data)
        return None

    @staticmethod
    def _scan(body: str) -> tuple[str, str] | None:
        """Return (rule_name, sha256_of_match) on first hit, else None."""
        for rule_name, pattern in _BLOCKLIST:
            m = pattern.search(body)
            if m:
                digest = hashlib.sha256(m.group(0).encode("utf-8")).hexdigest()[:16]
                return rule_name, digest
        return None

    def _on_violation(
        self,
        method: str,
        url: Any,
        rule: str,
        sample_hash: str,
    ) -> None:
        host: str | None = None
        try:
            host = urlparse(str(url)).hostname
        except Exception:  # pragma: no cover — defensive
            host = None
        logger.error(
            "opsec.egress_blocked",
            provider=self._provider,
            method=method,
            host=host,
            rule=rule,
            sample_sha256_prefix=sample_hash,
            enforcement=self._enforcement,
        )
        if self._metrics is not None:
            try:
                self._metrics.record_egress_block(provider=self._provider, reason=rule)
            except Exception:  # pragma: no cover — never break on metrics
                pass
