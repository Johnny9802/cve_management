"""System status and runtime configuration — /api/system

GET  /api/system/status         — probe all external services (latency + reachability)
GET  /api/system/status?service=nvd — probe single service
GET  /api/system/config         — list runtime config items (masked)
PATCH /api/system/config        — update a config item (stored in Valkey, survives restart)
"""
from __future__ import annotations

import json
import time
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.config import get_settings

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/system", tags=["system"])

# ── Config items definition ───────────────────────────────────────────────────

_CONFIG_ITEMS: list[dict] = [
    {
        "key": "NVD_API_KEY",
        "description": "NIST NVD API key — alza il rate limit da 5 a 50 req/30s. Gratuita su nvd.nist.gov/developers/request-an-api-key",
    },
    {
        "key": "VULNCHECK_API_KEY",
        "description": "VulnCheck NVD++ key — fonte primaria CVE (76.95% CPE coverage). Tier community gratuito su vulncheck.com",
    },
    {
        "key": "OPENCVE_API_KEY",
        "description": "OpenCVE API key — abilita query real-time per vendor/product. Gratuito su opencve.io",
    },
    {
        "key": "EPSS_PROVIDER",
        "description": "Provider score EPSS: 'first_org' (FIRST.org v3, default), 'vulncheck' (da NVD++ enrichment), 'disabled'",
    },
]

_REDIS_CFG_PREFIX = "cfg:"

# ── Service probes ────────────────────────────────────────────────────────────

_PROBES: dict[str, str] = {
    "nvd":   "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
    "circl": "https://vulnerability.circl.lu/api/search/apache/log4j?page=1",
    "epss":  "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
    "kev":   "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}


async def _probe_http(url: str, timeout: float = 5.0) -> dict[str, Any]:
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": "cve-management/0.1"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
        latency = int((time.monotonic() - t0) * 1000)
        if resp.is_success:
            return {"status": "ok", "latency_ms": latency}
        return {"status": "degraded", "latency_ms": latency, "detail": f"HTTP {resp.status_code}"}
    except httpx.TimeoutException:
        latency = int((time.monotonic() - t0) * 1000)
        return {"status": "error", "latency_ms": latency, "detail": "timeout"}
    except Exception as exc:
        return {"status": "error", "latency_ms": None, "detail": str(exc)[:120]}


async def _probe_db(request: Request) -> dict[str, Any]:
    t0 = time.monotonic()
    try:
        async with request.app.state.db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ok", "latency_ms": int((time.monotonic() - t0) * 1000)}
    except Exception as exc:
        return {"status": "error", "latency_ms": None, "detail": str(exc)[:120]}


async def _probe_redis(request: Request) -> dict[str, Any]:
    t0 = time.monotonic()
    try:
        await request.app.state.redis.ping()
        return {"status": "ok", "latency_ms": int((time.monotonic() - t0) * 1000)}
    except Exception as exc:
        return {"status": "error", "latency_ms": None, "detail": str(exc)[:120]}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/status")
async def system_status(request: Request, service: str | None = None) -> dict:
    import asyncio

    async def _all() -> dict:
        results = {}
        # HTTP probes in parallel
        http_tasks = {k: _probe_http(v) for k, v in _PROBES.items()}
        http_results = await asyncio.gather(*http_tasks.values())
        for k, r in zip(http_tasks.keys(), http_results):
            results[k] = r
        results["database"] = await _probe_db(request)
        results["redis"]    = await _probe_redis(request)
        return results

    if service:
        if service in _PROBES:
            return {service: await _probe_http(_PROBES[service])}
        if service == "database":
            return {"database": await _probe_db(request)}
        if service == "redis":
            return {"redis": await _probe_redis(request)}
        return {service: {"status": "unknown", "latency_ms": None}}

    return await _all()


@router.get("/config")
async def get_config(request: Request) -> dict:
    settings = get_settings()
    redis = request.app.state.redis

    def _mask(v: str | None) -> str | None:
        if not v:
            return None
        if len(v) <= 8:
            return "••••"
        return "••••" + v[-4:]

    def _env_val(key: str) -> str | None:
        mapping = {
            "NVD_API_KEY":       settings.nvd_api_key,
            "VULNCHECK_API_KEY": settings.vulncheck_api_key,
            "OPENCVE_API_KEY":   settings.opencve_api_key,
            "EPSS_PROVIDER":     "first_org",
        }
        return mapping.get(key) or None

    items = []
    for cfg in _CONFIG_ITEMS:
        key = cfg["key"]
        env_val = _env_val(key)

        # Check Redis override
        redis_val = await redis.get(f"{_REDIS_CFG_PREFIX}{key}")

        effective = redis_val or env_val
        source = "db" if redis_val else ("env" if env_val else "unset")

        # EPSS_PROVIDER is not a secret — show plaintext
        is_secret = key.endswith("_KEY")

        items.append({
            "key":          key,
            "is_set":       bool(effective),
            "value_masked": ((_mask(effective) if is_secret else effective) if effective else None),
            "source":       source,
            "description":  cfg["description"],
        })

    return {"items": items}


class ConfigUpdate(BaseModel):
    key: str
    value: str


@router.patch("/config")
async def update_config(body: ConfigUpdate, request: Request) -> dict:
    valid_keys = {c["key"] for c in _CONFIG_ITEMS}
    if body.key not in valid_keys:
        return JSONResponse(status_code=400, content={"error": f"Unknown config key: {body.key}"})

    redis = request.app.state.redis
    await redis.set(f"{_REDIS_CFG_PREFIX}{body.key}", body.value.strip())

    # Reload relevant settings in app state
    settings = get_settings()
    if body.key == "OPENCVE_API_KEY":
        try:
            request.app.state.opencve_client.settings.__dict__["opencve_api_key"] = body.value.strip()
        except Exception:
            pass

    logger.info("system.config_updated", key=body.key)
    return {"ok": True, "key": body.key}
