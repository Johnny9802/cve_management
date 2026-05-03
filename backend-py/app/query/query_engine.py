"""Multi-tier CVE query engine.

Tier 1 — Local DB        (always first, zero egress)
Tier 2 — CIRCL fallback  (only on cache miss, OpSec gate enforced in CirclClient)
Tier 3 — OpenCVE polling (background job only, not in hot path)
Tier 4 — vulnx lazy enrichment (P4) — opt-in via ``enrich_exploitability``

Query path:
  1. Query local DB (Tier 1).
  2. If total == 0 AND product has a resolved CPE → trigger CIRCL (Tier 2).
     a. CIRCL inserts new CVE stubs + findings into local DB.
     b. Re-query Tier 1 with the same filters.
  3. If ``enrich_exploitability=True`` AND result.total > 0:
     - identify CVEs with stale or missing ``exploitability_updated_at``
     - schedule a *background* vulnx refresh (Tier 4) that updates the
       row for the next request — current request is NOT delayed.
  4. Return result with `source` field indicating which tiers were used.
"""
from __future__ import annotations

import asyncio
from typing import Any

import asyncpg
import structlog
from redis.asyncio import Redis

from app.ingestion.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState
from app.ingestion.vulnx_client import VulnxClient
from app.models.finding import QueryFilters, QueryResult
from app.query.circl_client import CirclClient
from app.query.local_query import get_product_cpe, query_findings
from app.query.vulnx_enricher import schedule_lazy_refresh, select_stale

logger = structlog.get_logger(__name__)


async def query_cves_for_product(
    product_id: int,
    pool: asyncpg.Pool,
    redis: Redis,
    circl_client: CirclClient,
    circuit_breakers: dict[str, CircuitBreaker],
    filters: QueryFilters | None = None,
    *,
    enrich_exploitability: bool = False,
    vulnx_client: VulnxClient | None = None,
    background_tasks: set[asyncio.Task[Any]] | None = None,
) -> QueryResult:
    """Main entry point for the query layer.

    Args:
        product_id: ID of the product in the inventory.
        pool: asyncpg connection pool.
        redis: Redis/Valkey client.
        circl_client: Pre-initialized CIRCL client (holds rate governor).
        circuit_breakers: Shared circuit breaker registry.
        filters: Optional query filters (severity, status, pagination, ...).
    """
    if filters is None:
        filters = QueryFilters()

    # ── Tier 1: local DB ──────────────────────────────────────────────
    result = await query_findings(pool, product_id, filters)

    if result.total > 0:
        if enrich_exploitability:
            await _maybe_schedule_vulnx_enrichment(
                result=result,
                pool=pool,
                redis=redis,
                vulnx_client=vulnx_client,
                circuit_breakers=circuit_breakers,
                background_tasks=background_tasks,
            )
        return result

    # ── Tier 2: CIRCL fallback (only if no local findings) ────────────
    circl_circuit = circuit_breakers.get("circl")
    if circl_circuit and circl_circuit.state == CircuitState.OPEN:
        logger.warning("query_engine.circl_circuit_open", product_id=product_id)
        return result.model_copy(update={"source": "local_only"})

    normalized_cpe = await get_product_cpe(pool, product_id)
    if not normalized_cpe:
        logger.debug(
            "query_engine.no_cpe_skip_circl",
            product_id=product_id,
            hint="Resolve CPE first via /api/products/{id}/resolve-cpe",
        )
        return result.model_copy(update={"source": "local_only"})

    logger.info(
        "query_engine.circl_fallback",
        product_id=product_id,
        cpe=normalized_cpe,
    )

    try:
        new_count = 0

        async def _call_circl() -> int:
            return await circl_client.fetch_and_store(
                product_id=product_id,
                normalized_cpe=normalized_cpe,
                pool=pool,
                redis=redis,
            )

        if circl_circuit:
            new_count = await circl_circuit.call(_call_circl)
        else:
            new_count = await _call_circl()

    except CircuitOpenError as exc:
        logger.warning("query_engine.circl_circuit_open_mid", error=str(exc))
        return result.model_copy(update={"source": "local_only"})
    except Exception as exc:
        logger.error("query_engine.circl_error", error=str(exc))
        return result.model_copy(update={"source": "local_only"})

    if new_count == 0 and result.total == 0:
        return result.model_copy(update={"source": "local_only"})

    # Re-query Tier 1 now that CIRCL data has been inserted
    refreshed = await query_findings(pool, product_id, filters)

    if enrich_exploitability:
        await _maybe_schedule_vulnx_enrichment(
            result=refreshed,
            pool=pool,
            redis=redis,
            vulnx_client=vulnx_client,
            circuit_breakers=circuit_breakers,
            background_tasks=background_tasks,
        )

    return refreshed.model_copy(update={"source": "local+circl"})


# ---------------------------------------------------------------- Tier 4

async def _maybe_schedule_vulnx_enrichment(
    *,
    result: QueryResult,
    pool: asyncpg.Pool,
    redis: Redis,
    vulnx_client: VulnxClient | None,
    circuit_breakers: dict[str, CircuitBreaker],
    background_tasks: set[asyncio.Task[Any]] | None,
) -> None:
    """Inspect ``result`` for stale exploitability metadata and schedule a
    background vulnx refresh for those CVEs.

    The function is intentionally tolerant: it never raises; any error in
    Redis / vulnx surfaces only as a debug log line. The current
    request's response is unaffected.
    """
    if not result.findings or vulnx_client is None or background_tasks is None:
        return

    # Pull the freshness timestamp for each unique CVE in the page.
    cve_ids = list({f.cve_id for f in result.findings})
    if not cve_ids:
        return

    rows = await pool.fetch(
        "SELECT cve_id, exploitability_updated_at FROM cves WHERE cve_id = ANY($1)",
        cve_ids,
    )
    stale = select_stale([dict(r) for r in rows])
    if not stale:
        return

    circuit = circuit_breakers.get("vulnx")
    scheduled = await schedule_lazy_refresh(
        stale,
        pool=pool,
        redis=redis,
        vulnx=vulnx_client,
        circuit=circuit,
        background_tasks=background_tasks,
    )
    if scheduled:
        logger.info(
            "query_engine.tier4_lazy_refresh_scheduled",
            stale=len(stale),
            scheduled=scheduled,
        )
