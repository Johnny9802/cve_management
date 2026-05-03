"""Tier 4 — vulnx lazy enrichment (P4).

Opt-in helper used by ``query_engine.query_cves_for_product`` and by the
intel endpoint when the caller explicitly asks for fresh exploitability
data. The enrichment runs **in the background**: the user's request
returns the data we have now, and the refresh updates the row for the
next request.

Concurrency safety
------------------
* All scheduled background tasks are stored on
  ``app.state.background_tasks: set[asyncio.Task]`` so the lifespan can
  cancel them on shutdown.
* Per-CVE dedup uses a Redis SET (``vulnx:in_flight``) with a 60s TTL
  via ``SET key 1 EX 60 NX``. The first request claims the lock; later
  requests within the window are no-ops.
* The dedup window must be longer than the typical fetch latency
  (vulnx target: ~5s for batch=1) but short enough to recover from a
  hung task; 60s is a reasonable default.

OpSec
-----
vulnx receives only ``cve_id`` strings — same guarantee as P1's
exploitability_refresh job. The OpsecAwareClient enforces this even if
a future caller forgets.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import asyncpg
import structlog
from redis.asyncio import Redis

from app.ingestion.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)
from app.ingestion.vulnx_client import VulnxClient
from app.models.priority import compute_priority_score

logger = structlog.get_logger(__name__)

_INFLIGHT_TTL_SECONDS = 60
_STALE_HOURS_DEFAULT = 24


async def claim_inflight(redis: Redis, cve_id: str) -> bool:
    """Try to claim a per-CVE refresh slot. Returns True iff this caller
    owns the slot for the next ``_INFLIGHT_TTL_SECONDS``."""
    try:
        ok = await redis.set(
            f"vulnx:in_flight:{cve_id}",
            "1",
            ex=_INFLIGHT_TTL_SECONDS,
            nx=True,
        )
        return bool(ok)
    except Exception as exc:  # pragma: no cover — degrade open
        logger.warning("vulnx_enricher.redis_lock_error", error=str(exc))
        return True


async def release_inflight(redis: Redis, cve_id: str) -> None:
    try:
        await redis.delete(f"vulnx:in_flight:{cve_id}")
    except Exception:  # pragma: no cover
        pass


def select_stale(
    cve_rows: list[dict],
    *,
    stale_hours: int = _STALE_HOURS_DEFAULT,
) -> list[str]:
    """Filter ``cve_rows`` (mappings with ``cve_id`` + optional
    ``exploitability_updated_at``) to those that need a refresh."""
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=stale_hours)
    out: list[str] = []
    seen: set[str] = set()
    for row in cve_rows:
        cid = row.get("cve_id")
        if not cid or cid in seen:
            continue
        seen.add(cid)
        upd = row.get("exploitability_updated_at")
        if upd is None:
            out.append(cid)
            continue
        if hasattr(upd, "tzinfo") and upd.tzinfo is None:
            upd = upd.replace(tzinfo=timezone.utc)
        if upd < cutoff:
            out.append(cid)
    return out


async def schedule_lazy_refresh(
    cve_ids: list[str],
    *,
    pool: asyncpg.Pool,
    redis: Redis,
    vulnx: VulnxClient | None,
    circuit: CircuitBreaker | None,
    background_tasks: set[asyncio.Task],
) -> int:
    """Schedule a fire-and-forget refresh for the listed CVEs.

    Returns the number of CVEs *actually scheduled* (after dedup and
    circuit-breaker checks). Caller never awaits the resulting task —
    that is the whole point of the lazy pattern.
    """
    if not cve_ids:
        return 0
    if vulnx is None or not vulnx.is_configured:
        return 0
    if circuit and circuit.state == CircuitState.OPEN:
        logger.debug("vulnx_enricher.skip_circuit_open")
        return 0

    # Dedup by Redis SET NX; collect the CVEs we own.
    owned: list[str] = []
    for cid in cve_ids:
        if await claim_inflight(redis, cid):
            owned.append(cid)
    if not owned:
        return 0

    task = asyncio.create_task(
        _do_refresh(owned, pool=pool, redis=redis, vulnx=vulnx, circuit=circuit),
        name=f"vulnx_lazy:{owned[0]}+{len(owned)-1}",
    )
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    return len(owned)


async def _do_refresh(
    cve_ids: list[str],
    *,
    pool: asyncpg.Pool,
    redis: Redis,
    vulnx: VulnxClient,
    circuit: CircuitBreaker | None,
) -> None:
    try:
        if circuit is not None:
            intel = await circuit.call(vulnx.fetch_intel, cve_ids)
        else:
            intel = await vulnx.fetch_intel(cve_ids)
    except CircuitOpenError:
        logger.warning("vulnx_enricher.circuit_open_during_refresh")
        await _release_many(redis, cve_ids)
        return
    except Exception as exc:
        logger.warning("vulnx_enricher.refresh_error", error=str(exc))
        await _release_many(redis, cve_ids)
        return

    update_rows: list[tuple] = []
    not_found_rows: list[tuple] = []
    now = datetime.now(tz=timezone.utc)
    for cid in cve_ids:
        rec = intel.get(cid)
        if rec is None:
            not_found_rows.append((now, cid))
            continue
        update_rows.append(
            (rec.has_public_poc, rec.has_nuclei_template, rec.fetched_at, cid)
        )

    if update_rows:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """
                    UPDATE cves
                    SET has_public_poc            = $1,
                        has_nuclei_template       = $2,
                        exploitability_updated_at = $3,
                        updated_at                = NOW()
                    WHERE cve_id = $4
                    """,
                    update_rows,
                )
        await _recompute_finding_priorities(pool, [r[3] for r in update_rows])

    if not_found_rows:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """
                    UPDATE cves
                    SET exploitability_updated_at = $1
                    WHERE cve_id = $2
                      AND exploitability_updated_at IS DISTINCT FROM $1
                    """,
                    not_found_rows,
                )

    await _release_many(redis, cve_ids)
    logger.info(
        "vulnx_enricher.lazy_refresh.done",
        requested=len(cve_ids),
        updated=len(update_rows),
        not_found=len(not_found_rows),
    )


async def _release_many(redis: Redis, cve_ids: list[str]) -> None:
    for cid in cve_ids:
        await release_inflight(redis, cid)


async def _recompute_finding_priorities(
    pool: asyncpg.Pool, cve_ids: list[str]
) -> None:
    """Mirror of the recompute helper in exploitability_refresh.py."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT f.id,
                   f.priority_score AS old_score,
                   c.cve_id,
                   c.severity,
                   c.cvss_v3_score,
                   c.cvss_v2_score,
                   c.epss_score,
                   c.is_kev,
                   c.published_at,
                   c.has_public_poc,
                   c.has_nuclei_template
            FROM findings f
            JOIN cves     c ON c.cve_id = f.cve_id
            WHERE f.cve_id = ANY($1)
              AND f.status IN ('open', 'in_review', 'planned')
            """,
            cve_ids,
        )
    if not rows:
        return

    updates: list[tuple] = []
    for r in rows:
        cvss = r["cvss_v3_score"] or r["cvss_v2_score"]
        new_score = compute_priority_score(
            cvss_score=float(cvss) if cvss is not None else None,
            severity=r["severity"],
            epss_score=float(r["epss_score"]) if r["epss_score"] is not None else None,
            is_kev=bool(r["is_kev"]),
            published_at=r["published_at"],
            has_public_poc=bool(r["has_public_poc"]) if r["has_public_poc"] is not None else False,
            has_nuclei_template=bool(r["has_nuclei_template"])
            if r["has_nuclei_template"] is not None
            else False,
        )
        old = r["old_score"]
        old_int = int(old) if old is not None else None
        if new_score != old_int:
            updates.append((new_score, r["id"]))

    if updates:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    "UPDATE findings SET priority_score = $1, updated_at = NOW() WHERE id = $2",
                    updates,
                )
