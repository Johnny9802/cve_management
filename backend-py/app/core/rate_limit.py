"""Rate limit configuration (Sprint 1 — S1.5; Sprint 4 — S4.9).

Mitigates blocker R9 (trivial DoS): every public endpoint has a
per-IP budget enforced by slowapi.

Strategy
--------
* Default 200 req/min/IP applies everywhere unless overridden.
* Health endpoints are exempted via ``key_func`` short-circuit so
  liveness probes never burn budget.
* Heavy endpoints (``/api/cves/export``) are decorated individually
  with tighter limits at the route level — see app/api/routers/cves.py.

Storage backend (Sprint 4 / S4.9)
---------------------------------
* If ``RATE_LIMIT_STORAGE_URL`` is set (typically the same Redis we
  already require), slowapi shares counters across replicas — a
  client hitting two backend pods can't double its quota.
* Empty / unset = in-process MemoryStorage. Single-replica dev runs
  use this path.

The split lives behind a single ``_storage_uri()`` helper so flipping
modes is just an env var.
"""
from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

_EXEMPT_PATHS = (
    "/api/health",
    "/api/health/ready",
    "/api/health/metrics",
)


def _key(request: Request) -> str:
    if request.url.path in _EXEMPT_PATHS:
        return "health-probe"
    return get_remote_address(request)


def _storage_uri() -> str | None:
    """Resolve the slowapi storage URI.

    Priority:
      1. ``RATE_LIMIT_STORAGE_URL`` if set (explicit override),
      2. ``REDIS_URL`` if available (re-use the existing connection),
      3. None → MemoryStorage.

    slowapi expects either ``memory://`` or
    ``redis://[:password@]host:port/db`` (or ``rediss://`` for TLS),
    which is exactly what our ``REDIS_URL`` provides.
    """
    explicit = os.environ.get("RATE_LIMIT_STORAGE_URL", "").strip()
    if explicit:
        return explicit
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if redis_url and (redis_url.startswith("redis://") or redis_url.startswith("rediss://")):
        return redis_url
    return None


_storage = _storage_uri()

limiter = Limiter(
    key_func=_key,
    default_limits=["200/minute"],
    headers_enabled=True,
    # When None, slowapi defaults to MemoryStorage — keeps single-
    # instance dev unchanged. With a Redis URL, counters are shared
    # across every replica that points at the same instance.
    storage_uri=_storage if _storage else "memory://",
)
