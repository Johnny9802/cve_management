"""APScheduler 3.x — all background cron jobs.

Jobs:
  delta_sync       — VulnCheck/NVD delta every N hours
  epss_refresh     — EPSS scores for stale CVEs every 24 h
  kev_refresh      — CISA KEV catalog every 6 h
  opencve_poll     — OpenCVE API polling (only if API key set)
"""
from __future__ import annotations

from datetime import datetime

import asyncpg
import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from redis.asyncio import Redis

from app.core.config import Settings
from app.ingestion.circuit_breaker import CircuitBreaker
from app.ingestion.enrichment import run_epss_refresh, run_kev_refresh
from app.ingestion.epss_client import EpssClient
from app.ingestion.exploitability_refresh import run_exploitability_refresh
from app.ingestion.ingest_worker import run_smart_delta
from app.ingestion.kev_client import KevClient
from app.ingestion.nvd_client import NvdClient
from app.ingestion.vulncheck_client import VulnCheckClient
from app.ingestion.vulnx_client import VulnxClient
from app.query.opencve_client import OpenCveClient
from app.workers.daily_snapshot import capture_daily_snapshot
from app.workers.risk_acceptance_expirer import expire_risk_acceptances
from app.workers.sync_job_worker import drain_pending_jobs
from app.workers.webhook_worker import drain_pending_deliveries

logger = structlog.get_logger(__name__)


def create_scheduler(
    settings: Settings,
    db_pool: asyncpg.Pool,
    redis: Redis,
    vc_client: VulnCheckClient | None,
    nvd_client: NvdClient,
    epss_client: EpssClient,
    kev_client: KevClient,
    opencve_client: OpenCveClient,
    circuit_breakers: dict[str, CircuitBreaker],
    vulnx_client: VulnxClient | None = None,
) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler(timezone="UTC")

    # ── delta sync ────────────────────────────────────────────────────
    async def _delta_sync() -> None:
        log = logger.bind(job="delta_sync")
        log.info("scheduler.job.start")
        try:
            result = await run_smart_delta(
                pool=db_pool,
                vc_client=vc_client,
                nvd_client=nvd_client,
                circuits=circuit_breakers,
            )
            log.info(
                "scheduler.job.done",
                source=result.source,
                processed=result.processed,
                errors=result.errors,
                duration_ms=result.duration_ms,
            )
        except Exception as exc:
            log.error("scheduler.job.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _delta_sync,
        trigger=IntervalTrigger(hours=settings.delta_sync_interval_hours),
        id="delta_sync",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── EPSS refresh ──────────────────────────────────────────────────
    async def _epss_refresh() -> None:
        log = logger.bind(job="epss_refresh")
        log.info("scheduler.job.start")
        try:
            result = await run_epss_refresh(
                pool=db_pool,
                redis=redis,
                client=epss_client,
                circuit=circuit_breakers["epss"],
            )
            log.info("scheduler.job.done", updated=result.updated, skipped=result.skipped)
        except Exception as exc:
            log.error("scheduler.job.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _epss_refresh,
        trigger=IntervalTrigger(hours=settings.epss_refresh_interval_hours),
        id="epss_refresh",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── KEV refresh ───────────────────────────────────────────────────
    async def _kev_refresh() -> None:
        log = logger.bind(job="kev_refresh")
        log.info("scheduler.job.start")
        try:
            result = await run_kev_refresh(
                pool=db_pool,
                redis=redis,
                client=kev_client,
                circuit=circuit_breakers["kev"],
            )
            log.info("scheduler.job.done", updated=result.updated, skipped=result.skipped)
        except Exception as exc:
            log.error("scheduler.job.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _kev_refresh,
        trigger=IntervalTrigger(hours=settings.kev_refresh_interval_hours),
        id="kev_refresh",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── Data retention cleanup (daily) ───────────────────────────────
    # Keep: CVEs published in the current year + all KEV CVEs
    # Delete: CVEs published before current year AND not in KEV
    async def _retention_cleanup() -> None:
        log = logger.bind(job="retention_cleanup")
        try:
            async with db_pool.acquire() as conn, conn.transaction():
                # Delete dependent records first (epss_history has no CASCADE)
                await conn.execute(
                    """
                        DELETE FROM epss_history
                        WHERE cve_id IN (
                            SELECT cve_id FROM cves
                            WHERE EXTRACT(YEAR FROM published_at) < EXTRACT(YEAR FROM NOW())
                              AND is_kev = FALSE
                        )
                        """
                )
                result = await conn.execute(
                    """
                        DELETE FROM cves
                        WHERE EXTRACT(YEAR FROM published_at) < EXTRACT(YEAR FROM NOW())
                          AND is_kev = FALSE
                        """
                )
            deleted = int(result.split()[-1]) if result else 0
            if deleted:
                log.info("scheduler.retention.done", deleted=deleted)
            else:
                log.debug("scheduler.retention.nothing_to_delete")
        except Exception as exc:
            log.error("scheduler.retention.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _retention_cleanup,
        trigger=IntervalTrigger(hours=24),
        id="retention_cleanup",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── Queue-table cleanup (daily — DB-04, DB-05) ────────────────────
    # ``sync_jobs`` and ``webhook_deliveries`` are write-once / never-read
    # after completion. Without a janitor they grow indefinitely and slow
    # every queue scan. Retention keeps:
    #   * sync_jobs completed > 90d  → drop
    #   * sync_jobs dead     > 30d   → drop
    #   * webhook_deliveries delivered > 90d → drop
    async def _queue_cleanup() -> None:
        log = logger.bind(job="queue_cleanup")
        try:
            async with db_pool.acquire() as conn:
                done = await conn.execute(
                    """
                    DELETE FROM sync_jobs
                    WHERE status = 'completed'
                      AND completed_at < NOW() - INTERVAL '90 days'
                    """
                )
                dead = await conn.execute(
                    """
                    DELETE FROM sync_jobs
                    WHERE status = 'dead'
                      AND completed_at < NOW() - INTERVAL '30 days'
                    """
                )
                deliv = await conn.execute(
                    """
                    DELETE FROM webhook_deliveries
                    WHERE delivered_at IS NOT NULL
                      AND delivered_at < NOW() - INTERVAL '90 days'
                    """
                )
            log.info(
                "scheduler.queue_cleanup.done",
                sync_jobs_completed=int(done.split()[-1]) if done else 0,
                sync_jobs_dead=int(dead.split()[-1]) if dead else 0,
                webhook_deliveries=int(deliv.split()[-1]) if deliv else 0,
            )
        except Exception as exc:
            log.error("scheduler.queue_cleanup.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _queue_cleanup,
        trigger=IntervalTrigger(hours=24),
        id="queue_cleanup",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── sync_jobs DB queue poller ─────────────────────────────────────
    async def _sync_job_poll() -> None:
        try:
            count = await drain_pending_jobs(db_pool, redis)
            if count:
                logger.debug("scheduler.sync_job_poll.done", processed=count)
        except Exception as exc:
            logger.error("scheduler.sync_job_poll.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _sync_job_poll,
        trigger=IntervalTrigger(seconds=5),
        id="sync_job_poll",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── daily_snapshot (Sprint Dashboards 3) ──────────────────────────
    # Captures Executive-dashboard KPIs once per day. The lifespan also
    # runs it at startup so the dashboard is never blank on a fresh
    # install.
    async def _daily_snapshot() -> None:
        log = logger.bind(job="daily_snapshot")
        try:
            result = await capture_daily_snapshot(db_pool)
            log.info(
                "scheduler.job.done",
                captured_on=result.captured_on,
                risk_score=result.risk_score,
                duration_ms=result.duration_ms,
            )
        except Exception as exc:
            log.error("scheduler.job.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _daily_snapshot,
        trigger=IntervalTrigger(hours=24),
        id="daily_snapshot",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── expire_risk_acceptances (P8) ──────────────────────────────────
    # Daily sweep that flips approved risk acceptances past their
    # expires_at to 'expired', reopens accepted_risk findings, and
    # writes a system audit row inside the same transaction.
    async def _expire_risk_acceptances() -> None:
        log = logger.bind(job="expire_risk_acceptances")
        try:
            result = await expire_risk_acceptances(db_pool)
            log.info(
                "scheduler.job.done",
                expired=result.expired,
                reopened=result.reopened,
                duration_ms=result.duration_ms,
            )
        except Exception as exc:
            log.error("scheduler.job.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _expire_risk_acceptances,
        trigger=IntervalTrigger(hours=24),
        id="expire_risk_acceptances",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── webhook delivery worker (P7) ──────────────────────────────────
    # Polls webhook_deliveries every 10 s. Inside one tick the worker
    # claims up to _BATCH_SIZE rows with FOR UPDATE SKIP LOCKED, attempts
    # the POST, records the outcome, and reschedules failures with
    # exponential back-off.
    import os

    async def _webhook_dispatch() -> None:
        log = logger.bind(job="webhook_dispatch")
        try:
            allowlist = os.environ.get("WEBHOOK_HOST_ALLOWLIST", "")
            count = await drain_pending_deliveries(
                db_pool, settings, allowlist=allowlist
            )
            if count:
                log.debug("scheduler.webhook_dispatch.done", processed=count)
        except Exception as exc:
            log.error("scheduler.webhook_dispatch.error", error=str(exc), exc_info=True)

    scheduler.add_job(
        _webhook_dispatch,
        trigger=IntervalTrigger(seconds=10),
        id="webhook_dispatch",
        replace_existing=True,
        next_run_time=datetime.utcnow(),
    )

    # ── vulnx exploitability refresh (P1) ─────────────────────────────
    # Only register the job when vulnx is configured. The job batches
    # stale CVEs (default >7 days), pulls PoC/Nuclei flags from vulnx,
    # writes them back, and recomputes denormalised priority_score on
    # affected findings.
    if vulnx_client is not None and vulnx_client.is_configured:
        async def _vulnx_refresh() -> None:
            log = logger.bind(job="vulnx_refresh")
            log.info("scheduler.job.start")
            try:
                result = await run_exploitability_refresh(
                    pool=db_pool,
                    settings=settings,
                    client=vulnx_client,
                    circuit=circuit_breakers["vulnx"],
                )
                log.info(
                    "scheduler.job.done",
                    updated=result.updated,
                    not_found=result.not_found,
                    errors=result.errors,
                    daily_limit_hit=result.daily_limit_hit,
                    duration_ms=result.duration_ms,
                )
            except Exception as exc:
                log.error("scheduler.job.error", error=str(exc), exc_info=True)

        scheduler.add_job(
            _vulnx_refresh,
            trigger=IntervalTrigger(hours=settings.vulnx_refresh_interval_hours),
            id="vulnx_refresh",
            replace_existing=True,
            next_run_time=datetime.utcnow(),
        )

    # ── OpenCVE poll (only if API key configured) ─────────────────────
    if opencve_client.is_configured:
        async def _opencve_poll() -> None:
            log = logger.bind(job="opencve_poll")
            log.info("scheduler.job.start")
            try:
                new_count = await opencve_client.poll_subscriptions(db_pool)
                log.info("scheduler.job.done", new_cves=new_count)
            except Exception as exc:
                log.error("scheduler.job.error", error=str(exc), exc_info=True)

        scheduler.add_job(
            _opencve_poll,
            trigger=IntervalTrigger(hours=settings.delta_sync_interval_hours),
            id="opencve_poll",
            replace_existing=True,
            next_run_time=datetime.utcnow(),
        )

    return scheduler
