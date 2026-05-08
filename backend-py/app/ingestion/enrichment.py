"""Enrichment orchestration: update cves with EPSS scores and CISA KEV flags.

Designed to run as periodic cron jobs independent of the ingestion pipeline.
Both functions are idempotent and safe to re-run without duplicating data.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import date

import asyncpg
import structlog
from redis.asyncio import Redis

from app.ingestion.circuit_breaker import CircuitBreaker, CircuitOpenError
from app.ingestion.epss_client import EpssClient
from app.ingestion.kev_client import KevClient

logger = structlog.get_logger(__name__)

_EPSS_PAGE = 5_000   # CVEs fetched per DB query for enrichment
_EPSS_STALE_HOURS = 24

_STALE_CVE_SQL = """
    SELECT cve_id FROM cves
    WHERE epss_updated_at IS NULL
       OR epss_updated_at < NOW() - INTERVAL '{hours} hours'
    ORDER BY
        CASE WHEN is_kev THEN 0 ELSE 1 END,
        COALESCE(cvss_v3_score, cvss_v2_score, 0) DESC
    LIMIT $1
"""

_UPDATE_EPSS_SQL = """
    UPDATE cves
    SET epss_score      = $1,
        epss_percentile = $2,
        epss_updated_at = NOW()
    WHERE cve_id = $3
"""

_INSERT_EPSS_HISTORY_SQL = """
    INSERT INTO epss_history (cve_id, score, percentile)
    VALUES ($1, $2, $3)
"""

_UPDATE_KEV_SQL = """
    UPDATE cves
    SET is_kev         = TRUE,
        kev_added_date = $1
    WHERE cve_id = $2
      AND (is_kev = FALSE OR kev_added_date IS NULL)
"""


@dataclass
class EnrichResult:
    job: str
    updated: int
    skipped: int
    errors: int
    duration_ms: int


# ------------------------------------------------------------------ #
# EPSS enrichment                                                      #
# ------------------------------------------------------------------ #

async def run_epss_refresh(
    pool: asyncpg.Pool,
    redis: Redis,
    client: EpssClient,
    circuit: CircuitBreaker,
) -> EnrichResult:
    """Fetch EPSS scores for stale CVEs and write them back to the DB."""
    t0 = time.monotonic()
    updated = errors = skipped = 0

    async def _do() -> None:
        nonlocal updated, errors, skipped

        async with pool.acquire() as conn:
            rows = await conn.fetch(
                _STALE_CVE_SQL.format(hours=_EPSS_STALE_HOURS), _EPSS_PAGE
            )

        if not rows:
            logger.debug("epss.refresh.nothing_stale")
            return

        cve_ids = [r["cve_id"] for r in rows]
        logger.info("epss.refresh.start", count=len(cve_ids))

        scores = await client.fetch_scores(cve_ids, redis)

        epss_rows: list[tuple] = []
        history_rows: list[tuple] = []

        for cve_id in cve_ids:
            score = scores.get(cve_id)
            if score is None:
                skipped += 1
                continue
            epss_rows.append((score.score, score.percentile, cve_id))
            history_rows.append((cve_id, score.score, score.percentile))

        if not epss_rows:
            return

        async with pool.acquire() as conn, conn.transaction():
            await conn.executemany(_UPDATE_EPSS_SQL, epss_rows)
            await conn.executemany(_INSERT_EPSS_HISTORY_SQL, history_rows)
            updated += len(epss_rows)

        logger.info("epss.refresh.done", updated=updated, skipped=skipped)

    try:
        await circuit.call(_do)
    except CircuitOpenError as exc:
        logger.warning("epss.refresh.circuit_open", error=str(exc))
        errors += 1
    except Exception as exc:
        logger.error("epss.refresh.failed", error=str(exc))
        errors += 1
        raise

    return EnrichResult(
        job="epss_refresh",
        updated=updated,
        skipped=skipped,
        errors=errors,
        duration_ms=int((time.monotonic() - t0) * 1000),
    )


# ------------------------------------------------------------------ #
# CISA KEV enrichment                                                  #
# ------------------------------------------------------------------ #

async def run_kev_refresh(
    pool: asyncpg.Pool,
    redis: Redis,
    client: KevClient,
    circuit: CircuitBreaker,
) -> EnrichResult:
    """Fetch the KEV catalog and mark matching CVEs in the DB."""
    t0 = time.monotonic()
    updated = errors = skipped = 0

    async def _do() -> None:
        nonlocal updated, skipped

        catalog: dict[str, date] = await client.get_catalog(redis)
        if not catalog:
            logger.warning("kev.refresh.empty_catalog")
            return

        logger.info("kev.refresh.start", catalog_size=len(catalog))

        # Only update CVEs we actually have in our mirror
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT cve_id FROM cves WHERE cve_id = ANY($1)", list(catalog))

        to_update = [(catalog[r["cve_id"]], r["cve_id"]) for r in rows]
        skipped = len(catalog) - len(to_update)

        if not to_update:
            return

        async with pool.acquire() as conn, conn.transaction():
            await conn.executemany(_UPDATE_KEV_SQL, to_update)
            # executemany doesn't return a rowcount easily; track via to_update length
            updated = len(to_update)

        logger.info("kev.refresh.done", updated=updated, skipped=skipped)

    try:
        await circuit.call(_do)
    except CircuitOpenError as exc:
        logger.warning("kev.refresh.circuit_open", error=str(exc))
        errors += 1
    except Exception as exc:
        logger.error("kev.refresh.failed", error=str(exc))
        errors += 1
        raise

    return EnrichResult(
        job="kev_refresh",
        updated=updated,
        skipped=skipped,
        errors=errors,
        duration_ms=int((time.monotonic() - t0) * 1000),
    )
