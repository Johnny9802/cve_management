"""Health and metrics endpoints.

GET /api/health        — liveness + dependency readiness
GET /api/health/ready  — readiness only (suitable for k8s readinessProbe)
GET /api/health/metrics — in-process metrics JSON (provider counters + latency)
"""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Request
from pydantic import BaseModel

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["health"])


class DependencyStatus(BaseModel):
    status: str
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    dependencies: dict[str, DependencyStatus]
    circuit_breakers: dict[str, Any] | None = None
    sync_state: list[dict[str, Any]] | None = None
    scheduler_jobs: list[dict[str, Any]] | None = None


async def _check_postgres(request: Request) -> DependencyStatus:
    try:
        async with request.app.state.db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return DependencyStatus(status="ok")
    except Exception as exc:
        logger.error("health.postgres_fail", error=str(exc))
        return DependencyStatus(status="error", detail="connection failed")


async def _check_valkey(request: Request) -> DependencyStatus:
    try:
        await request.app.state.redis.ping()
        return DependencyStatus(status="ok")
    except Exception as exc:
        logger.error("health.valkey_fail", error=str(exc))
        return DependencyStatus(status="error", detail="connection failed")


async def _get_sync_state(request: Request) -> list[dict[str, Any]]:
    try:
        rows = await request.app.state.db_pool.fetch(
            "SELECT source, last_success_at, last_mod_date, total_ingested, last_error FROM sync_state"
        )
        return [dict(r) for r in rows]
    except Exception:
        return []


def _get_circuit_breakers(request: Request) -> dict[str, Any]:
    try:
        return {
            name: cb.status_snapshot
            for name, cb in request.app.state.circuit_breakers.items()
        }
    except AttributeError:
        return {}


def _get_scheduler_jobs(request: Request) -> list[dict[str, Any]]:
    try:
        scheduler = request.app.state.scheduler
        return [
            {
                "id": job.id,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            }
            for job in scheduler.get_jobs()
        ]
    except AttributeError:
        return []


@router.get("/api/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    deps = {
        "postgres": await _check_postgres(request),
        "valkey": await _check_valkey(request),
    }
    overall = "ok" if all(d.status == "ok" for d in deps.values()) else "degraded"

    return HealthResponse(
        status=overall,
        version="0.1.0",
        dependencies=deps,
        circuit_breakers=_get_circuit_breakers(request),
        sync_state=await _get_sync_state(request),
        scheduler_jobs=_get_scheduler_jobs(request),
    )


@router.get("/api/health/ready")
async def readiness(request: Request) -> dict:
    """Lightweight readiness probe — checks DB + Valkey only."""
    pg = await _check_postgres(request)
    vk = await _check_valkey(request)
    ok = pg.status == "ok" and vk.status == "ok"
    return {"ready": ok, "postgres": pg.status, "valkey": vk.status}


@router.get("/api/health/metrics")
async def metrics(request: Request) -> dict:
    """In-process metrics: HTTP counters + per-provider counters + latency percentiles."""
    try:
        return request.app.state.metrics.snapshot()
    except AttributeError:
        return {"error": "metrics not available"}
