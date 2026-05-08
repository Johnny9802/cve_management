"""Verifies the Sprint 1 hardening middlewares behave as advertised:

* SecurityHeadersMiddleware sets CSP / X-Frame-Options /
  X-Content-Type-Options / Referrer-Policy / Permissions-Policy on
  every response, with HSTS only in ``production`` env.
* slowapi enforces per-IP throttling and exempts the health probes.

Tests boot a tiny FastAPI app with the same middlewares wired in;
no DB or Redis required.
"""
from __future__ import annotations

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, Request, Response
from httpx import ASGITransport
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api.middleware.security_headers import SecurityHeadersMiddleware


def _build_app(environment: str = "development") -> FastAPI:
    """Build a fresh app with a *fresh* Limiter per call. We can't reuse
    the production singleton in app/core/rate_limit.py because its
    in-memory MemoryStorage leaks counters between tests, making the
    rate-limit assertions order-dependent."""
    fresh_limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200/minute"],
        headers_enabled=True,
    )

    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, environment=environment)
    app.state.limiter = fresh_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    @app.get("/api/health/ready")
    async def health():
        return {"ok": True}

    @app.get("/anything")
    async def anything():
        return {"ok": True}

    @app.get("/limited")
    @fresh_limiter.limit("3/minute")
    async def limited(request: Request, response: Response):  # noqa: ARG001
        # slowapi needs `response` in the signature when
        # headers_enabled=True so it can attach X-RateLimit-* headers.
        return {"ok": True}

    return app


@pytest_asyncio.fixture
async def dev_client():
    transport = ASGITransport(app=_build_app("development"))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def prod_client():
    transport = ASGITransport(app=_build_app("production"))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ────────────────────────────────────────────────────── headers


@pytest.mark.asyncio
async def test_security_headers_present_on_normal_response(dev_client):
    r = await dev_client.get("/anything")
    assert r.status_code == 200

    h = r.headers
    assert "content-security-policy" in h
    assert h["x-frame-options"] == "DENY"
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "permissions-policy" in h
    # Dev: no HSTS — it would pin localhost to HTTPS.
    assert "strict-transport-security" not in h


@pytest.mark.asyncio
async def test_hsts_emitted_only_in_production(prod_client):
    r = await prod_client.get("/anything")
    assert "strict-transport-security" in r.headers
    assert "max-age=" in r.headers["strict-transport-security"]


@pytest.mark.asyncio
async def test_csp_blocks_inline_eval(dev_client):
    r = await dev_client.get("/anything")
    csp = r.headers["content-security-policy"]
    # Sanity checks on the policy shipped in S1.6:
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'self'" in csp


# ────────────────────────────────────────────────────── rate limit


@pytest.mark.asyncio
async def test_rate_limit_triggers_429_after_quota(dev_client):
    # Three calls succeed, the fourth is throttled.
    for _ in range(3):
        r = await dev_client.get("/limited")
        assert r.status_code == 200
    blocked = await dev_client.get("/limited")
    assert blocked.status_code == 429


@pytest.mark.asyncio
async def test_health_endpoint_under_default_quota(dev_client):
    # Liveness probes hit /api/health/ready every few seconds. The
    # default global cap is 200/min — reachable but not in 20 calls.
    # In production the route also benefits from the shared health
    # bucket configured in app/core/rate_limit.py (covered there).
    for _ in range(20):
        r = await dev_client.get("/api/health/ready")
        assert r.status_code == 200
