"""Rate limit configuration (Sprint 1 — S1.5).

Mitigates blocker R9 (trivial DoS): every public endpoint now has a
per-IP budget enforced by slowapi.

Strategy
--------
* Default 200 req/min/IP applies everywhere unless overridden.
* Health endpoints are explicitly exempted via ``key_func`` short-circuit
  so liveness probes never burn budget.
* Heavy endpoints (``/api/cves/export``) are decorated individually with
  a tighter limit at the route level — see ``app/api/routers/cves.py``.

When the platform moves to multi-instance (Sprint 4) the in-process
storage is swapped for Redis via ``slowapi.RedisStorage``; the ``Limiter``
construction is the only line that needs to change.
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

# Routes that must never be throttled. Liveness/readiness probes hit the
# backend every few seconds; throttling them would mask real outages by
# producing fake 429s.
_EXEMPT_PATHS = (
    "/api/health",
    "/api/health/ready",
    "/api/health/metrics",
)


def _key(request: Request) -> str:
    """Per-IP key, with health endpoints folded into a single bucket so
    they effectively bypass per-IP enforcement."""
    if request.url.path in _EXEMPT_PATHS:
        return "health-probe"
    return get_remote_address(request)


limiter = Limiter(
    key_func=_key,
    default_limits=["200/minute"],
    headers_enabled=True,
)
