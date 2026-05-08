import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.middleware.error_handler import add_error_handler
from app.api.middleware.security_headers import SecurityHeadersMiddleware
from app.core.rate_limit import limiter
from app.api.routers import audit as audit_router
from app.api.routers import (
    circl_router,
    cpe_suggest,
    cves,
    dashboard,
    findings,
    health,
    live,
    products,
)
from app.api.routers import intel as intel_router
from app.api.routers import risk_acceptance as risk_acceptance_router
from app.api.routers import sla as sla_router
from app.api.routers import system as system_router
from app.api.routers import webhooks as webhooks_router
from app.core.cache import create_redis
from app.core.config import get_settings
from app.core.db import create_pool
from app.core.logging import configure_logging
from app.core.metrics import MetricsRegistry
from app.core.migrations import run_migrations
from app.ingestion.circuit_breaker import build_circuit_breakers
from app.ingestion.epss_client import EpssClient
from app.ingestion.kev_client import KevClient
from app.ingestion.nvd_client import NvdClient
from app.ingestion.rate_governor import build_governors
from app.ingestion.vulncheck_client import VulnCheckClient
from app.ingestion.vulnx_client import VulnxClient
from app.query.circl_client import CirclClient
from app.query.opencve_client import OpenCveClient
from app.workers.scheduler import create_scheduler

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("startup.begin", environment=settings.environment)

    if settings.auto_migrate:
        await asyncio.to_thread(run_migrations, settings.database_url)

    app.state.db_pool = await create_pool(settings.database_url)
    app.state.redis = await create_redis(settings.redis_url)
    app.state.settings = settings
    # P4 Tier 4 lazy enrichment: background tasks tracked here so the
    # lifespan can cancel them cleanly on shutdown.
    app.state.background_tasks = set()

    metrics = MetricsRegistry()
    app.state.metrics = metrics

    governors = build_governors(settings)
    app.state.rate_governors = governors

    circuit_breakers = build_circuit_breakers()
    app.state.circuit_breakers = circuit_breakers

    # Attach metrics to each rate governor so rate-limited events are counted
    for provider_name, governor in governors.items():
        governor.attach_metrics(metrics.provider(provider_name))

    nvd_client = NvdClient(settings=settings, governor=governors["nvd"])
    nvd_client._client.attach_metrics(metrics)
    app.state.nvd_client = nvd_client

    epss_client = EpssClient(settings=settings, governor=governors["epss"])
    epss_client._client.attach_metrics(metrics)
    app.state.epss_client = epss_client

    kev_client = KevClient(settings=settings, governor=governors["kev"])
    kev_client._client.attach_metrics(metrics)
    app.state.kev_client = kev_client

    circl_client = CirclClient(settings=settings, governor=governors["circl"])
    circl_client._client.attach_metrics(metrics)
    app.state.circl_client = circl_client

    opencve_client = OpenCveClient(settings=settings, governor=governors["epss"])
    opencve_client._client.attach_metrics(metrics)
    app.state.opencve_client = opencve_client

    if settings.vulncheck_api_key:
        vc_client = VulnCheckClient(settings=settings, governor=governors["vulncheck"])
        vc_client._client.attach_metrics(metrics)
        app.state.vulncheck_client = vc_client
        logger.info("startup.vulncheck_client_ready")
    else:
        app.state.vulncheck_client = None
        logger.warning(
            "startup.vulncheck_key_missing",
            hint="Set VULNCHECK_API_KEY to enable NVD++ ingestion",
        )

    # vulnx (P1): instantiated unconditionally — intel endpoint may use it
    # in degraded mode even without an API key, and absence of the key is
    # logged once to avoid noisy startup output.
    vulnx_client = VulnxClient(settings=settings, governor=governors["vulnx"])
    vulnx_client.attach_metrics(metrics)
    app.state.vulnx_client = vulnx_client
    if vulnx_client.is_configured:
        logger.info("startup.vulnx_client_ready")
    else:
        logger.info(
            "startup.vulnx_key_missing",
            hint="Set VULNX_API_KEY to enable exploitability refresh",
        )

    scheduler = create_scheduler(
        settings=settings,
        db_pool=app.state.db_pool,
        redis=app.state.redis,
        vc_client=app.state.vulncheck_client,
        nvd_client=nvd_client,
        epss_client=epss_client,
        kev_client=kev_client,
        opencve_client=opencve_client,
        vulnx_client=vulnx_client,
        circuit_breakers=circuit_breakers,
    )
    scheduler.start()
    app.state.scheduler = scheduler
    logger.info(
        "startup.scheduler_started",
        jobs=["delta_sync", "epss_refresh", "kev_refresh"],
        delta_interval_hours=settings.delta_sync_interval_hours,
    )

    logger.info("startup.complete")
    yield

    logger.info("shutdown.begin")
    app.state.scheduler.shutdown(wait=False)

    # Drain any in-flight Tier 4 background tasks before closing pools.
    pending = list(getattr(app.state, "background_tasks", []))
    if pending:
        logger.info("shutdown.cancel_background_tasks", count=len(pending))
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    if app.state.vulncheck_client:
        await app.state.vulncheck_client.aclose()
    if getattr(app.state, "vulnx_client", None):
        await app.state.vulnx_client.aclose()
    await app.state.nvd_client.aclose()
    await app.state.epss_client.aclose()
    await app.state.kev_client.aclose()
    await app.state.circl_client.aclose()
    await app.state.opencve_client.aclose()
    await app.state.db_pool.close()
    await app.state.redis.aclose()
    logger.info("shutdown.complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="CVE Management Platform",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
        redirect_slashes=False,  # prevents 307 loop with Next.js trailing-slash rewrite
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.allowed_origin],
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID", "Authorization"],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(SecurityHeadersMiddleware, environment=settings.environment)

    # Rate limiting (S1.5). Default 200/min/IP; health probes exempt;
    # heavy endpoints decorated individually with stricter caps.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    add_error_handler(app)
    app.include_router(health.router)
    app.include_router(products.router)
    app.include_router(cves.router)
    app.include_router(intel_router.router)
    app.include_router(findings.router)
    app.include_router(dashboard.router)
    app.include_router(live.router)
    app.include_router(cpe_suggest.router)
    app.include_router(circl_router.router)
    app.include_router(webhooks_router.router)
    # Sprint 3 — risk acceptance + SLA + read-only audit log
    app.include_router(risk_acceptance_router.router)
    app.include_router(risk_acceptance_router.router_summary)
    app.include_router(sla_router.router)
    app.include_router(audit_router.router)
    app.include_router(system_router.router)

    return app


app = create_app()
