"""Ingestion orchestration: upsert logic, Arq job handlers, sync_state checkpoint."""
from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import asyncpg
import structlog

from app.ingestion.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState
from app.ingestion.vulncheck_client import VulnCheckClient
from app.models.nvd import NvdCveRecord

if TYPE_CHECKING:
    from app.ingestion.nvd_client import NvdClient

logger = structlog.get_logger(__name__)

_UPSERT_BATCH = 500   # rows per executemany call

_UPSERT_SQL = """
    INSERT INTO cves (
        cve_id, source, raw_payload, cvss_v3_score, cvss_v3_vector,
        cvss_v2_score, severity, published_at, last_modified_at
    )
    VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9)
    ON CONFLICT (cve_id) DO UPDATE SET
        raw_payload      = EXCLUDED.raw_payload,
        cvss_v3_score    = EXCLUDED.cvss_v3_score,
        cvss_v3_vector   = EXCLUDED.cvss_v3_vector,
        cvss_v2_score    = EXCLUDED.cvss_v2_score,
        severity         = EXCLUDED.severity,
        last_modified_at = EXCLUDED.last_modified_at,
        source           = EXCLUDED.source,
        updated_at       = NOW()
    WHERE cves.last_modified_at < EXCLUDED.last_modified_at
       OR cves.last_modified_at IS NULL
"""

_CHECKPOINT_SQL = """
    UPDATE sync_state
    SET last_success_at = NOW(),
        last_mod_date   = $1,
        total_ingested  = total_ingested + $2,
        last_error      = NULL,
        updated_at      = NOW()
    WHERE source = $3
"""

_ERROR_SQL = """
    UPDATE sync_state SET last_error = $1, updated_at = NOW() WHERE source = $2
"""


@dataclass
class IngestResult:
    source: str
    processed: int
    errors: int
    duration_ms: int


async def _upsert_batched(
    pool: asyncpg.Pool,
    records: AsyncGenerator[NvdCveRecord, None],
    source: str,
) -> tuple[int, int]:
    """Stream records into the DB in batches. Returns (processed, errors)."""
    processed = 0
    errors = 0
    batch: list[tuple] = []

    async def _flush(conn: asyncpg.Connection) -> None:
        nonlocal processed, errors
        if not batch:
            return
        try:
            await conn.executemany(_UPSERT_SQL, batch)
            processed += len(batch)
        except Exception as exc:
            logger.error("ingest.upsert_batch_error", error=str(exc), batch_size=len(batch))
            errors += len(batch)
        batch.clear()

    async with pool.acquire() as conn:
        async for record in records:
            batch.append(record.to_row(source))
            if len(batch) >= _UPSERT_BATCH:
                await _flush(conn)

        await _flush(conn)  # flush remainder

    return processed, errors


async def run_bulk_ingest(
    pool: asyncpg.Pool,
    client: VulnCheckClient,
    circuit: CircuitBreaker,
) -> IngestResult:
    """Full initial load from VulnCheck (bulk S3 or full delta fallback)."""
    t0 = time.monotonic()
    source = "vulncheck_nvd"

    async def _do() -> tuple[int, int]:
        return await _upsert_batched(pool, client.iter_bulk(), source)

    try:
        processed, errors = await circuit.call(_do)
    except CircuitOpenError as exc:
        logger.error("ingest.bulk_circuit_open", error=str(exc))
        await _record_error(pool, source, str(exc))
        return IngestResult(source=source, processed=0, errors=1, duration_ms=0)
    except Exception as exc:
        logger.error("ingest.bulk_failed", error=str(exc))
        await _record_error(pool, source, str(exc))
        raise

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    await _checkpoint(pool, source, datetime.now(tz=UTC), processed)
    logger.info(
        "ingest.bulk_complete",
        processed=processed,
        errors=errors,
        duration_ms=elapsed_ms,
    )
    return IngestResult(source=source, processed=processed, errors=errors, duration_ms=elapsed_ms)


async def run_delta_ingest(
    pool: asyncpg.Pool,
    client: VulnCheckClient,
    circuit: CircuitBreaker,
) -> IngestResult:
    """Incremental sync: fetch CVEs modified since last checkpoint."""
    t0 = time.monotonic()
    source = "vulncheck_nvd"
    last_mod = await _get_last_mod_date(pool, source)

    async def _do() -> tuple[int, int]:
        return await _upsert_batched(pool, client.iter_delta(last_mod), source)

    try:
        processed, errors = await circuit.call(_do)
    except CircuitOpenError as exc:
        logger.warning("ingest.delta_circuit_open", error=str(exc))
        return IngestResult(source=source, processed=0, errors=1, duration_ms=0)
    except Exception as exc:
        logger.error("ingest.delta_failed", error=str(exc))
        await _record_error(pool, source, str(exc))
        raise

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    await _checkpoint(pool, source, datetime.now(tz=UTC), processed)
    logger.info(
        "ingest.delta_complete",
        processed=processed,
        errors=errors,
        duration_ms=elapsed_ms,
        since=last_mod.isoformat() if last_mod else "full",
    )
    return IngestResult(source=source, processed=processed, errors=errors, duration_ms=elapsed_ms)


# ------------------------------------------------------------------ #
# Arq job handlers                                                    #
# ------------------------------------------------------------------ #

async def job_bulk_ingest(ctx: dict) -> dict:
    """Arq job: full VulnCheck bulk load. Enqueued once on first startup."""
    pool: asyncpg.Pool = ctx["db_pool"]
    client: VulnCheckClient = ctx["vulncheck_client"]
    circuit: CircuitBreaker = ctx["circuit_breakers"]["vulncheck"]

    result = await run_bulk_ingest(pool, client, circuit)
    return {
        "source": result.source,
        "processed": result.processed,
        "errors": result.errors,
        "duration_ms": result.duration_ms,
    }


async def job_delta_ingest(ctx: dict) -> dict:
    """Arq job: incremental VulnCheck delta sync. Triggered by APScheduler."""
    pool: asyncpg.Pool = ctx["db_pool"]
    client: VulnCheckClient = ctx["vulncheck_client"]
    circuit: CircuitBreaker = ctx["circuit_breakers"]["vulncheck"]

    result = await run_delta_ingest(pool, client, circuit)
    return {
        "source": result.source,
        "processed": result.processed,
        "errors": result.errors,
        "duration_ms": result.duration_ms,
    }


# ------------------------------------------------------------------ #
# NVD fallback + smart delta                                          #
# ------------------------------------------------------------------ #

async def run_nvd_delta_ingest(
    pool: asyncpg.Pool,
    client: NvdClient,
    circuit: CircuitBreaker,
) -> IngestResult:
    """Incremental NVD API v2 sync — used when VulnCheck is unavailable."""

    t0 = time.monotonic()
    source = "nvd_api"
    last_mod = await _get_last_mod_date(pool, source)

    async def _do() -> tuple[int, int]:
        return await _upsert_batched(pool, client.iter_delta(last_mod), source)

    try:
        processed, errors = await circuit.call(_do)
    except CircuitOpenError as exc:
        logger.warning("ingest.nvd_circuit_open", error=str(exc))
        return IngestResult(source=source, processed=0, errors=1, duration_ms=0)
    except Exception as exc:
        logger.error("ingest.nvd_delta_failed", error=str(exc))
        await _record_error(pool, source, str(exc))
        raise

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    await _checkpoint(pool, source, datetime.now(tz=UTC), processed)
    logger.info(
        "ingest.nvd_delta_complete",
        processed=processed,
        errors=errors,
        duration_ms=elapsed_ms,
        since=last_mod.isoformat() if last_mod else "full",
    )
    return IngestResult(source=source, processed=processed, errors=errors, duration_ms=elapsed_ms)


async def run_smart_delta(
    pool: asyncpg.Pool,
    vc_client: VulnCheckClient | None,
    nvd_client: NvdClient,
    circuits: dict[str, CircuitBreaker],
) -> IngestResult:
    """Try VulnCheck delta first; fall back to NVD API v2 on failure or circuit open."""
    vc_circuit = circuits["vulncheck"]
    nvd_circuit = circuits["nvd"]

    if vc_client is not None and vc_circuit.state != CircuitState.OPEN:
        try:
            return await run_delta_ingest(pool, vc_client, vc_circuit)
        except Exception as exc:
            logger.warning(
                "ingest.smart.vulncheck_failed_fallback_to_nvd", error=str(exc)
            )

    logger.info("ingest.smart.using_nvd")
    return await run_nvd_delta_ingest(pool, nvd_client, nvd_circuit)


async def job_smart_delta(ctx: dict) -> dict:
    """Arq job: smart delta — VulnCheck primary, NVD fallback."""
    pool: asyncpg.Pool = ctx["db_pool"]
    vc_client = ctx.get("vulncheck_client")
    nvd_client = ctx["nvd_client"]
    circuits: dict[str, CircuitBreaker] = ctx["circuit_breakers"]

    result = await run_smart_delta(pool, vc_client, nvd_client, circuits)
    return {
        "source": result.source,
        "processed": result.processed,
        "errors": result.errors,
        "duration_ms": result.duration_ms,
    }


# ------------------------------------------------------------------ #
# sync_state helpers                                                  #
# ------------------------------------------------------------------ #

async def _get_last_mod_date(pool: asyncpg.Pool, source: str) -> datetime | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT last_mod_date FROM sync_state WHERE source = $1", source
        )
    if row and row["last_mod_date"]:
        dt = row["last_mod_date"]
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    return None


async def _checkpoint(
    pool: asyncpg.Pool, source: str, last_mod: datetime, count: int
) -> None:
    async with pool.acquire() as conn:
        await conn.execute(_CHECKPOINT_SQL, last_mod, count, source)


async def _record_error(pool: asyncpg.Pool, source: str, error: str) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute(_ERROR_SQL, error[:500], source)
    except Exception as exc:
        logger.error("ingest.record_error_failed", error=str(exc))
