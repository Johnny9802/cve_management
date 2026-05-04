"""Dashboard router — /api/dashboard

Cached: `dashboard:stats` (5 min), `dashboard:timeline` (5 min).

Note: asyncpg connections execute one query at a time — queries run sequentially
on a single connection (no asyncio.gather with the same conn object).
"""
from __future__ import annotations

import json
from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, Request
from redis.asyncio import Redis

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_STATS_TTL = 300
_TIMELINE_TTL = 300


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


def _get_redis(request: Request) -> Redis:
    return request.app.state.redis


@router.get("")
async def dashboard_stats(
    pool: asyncpg.Pool = Depends(_get_pool),
    redis: Redis = Depends(_get_redis),
) -> dict:
    cached = await redis.get("dashboard:stats")
    if cached:
        return json.loads(cached)

    async with pool.acquire() as conn:
        total_row      = await conn.fetchrow("SELECT COUNT(*) FROM cves")
        severity_rows  = await conn.fetch("""
            SELECT severity, COUNT(*) AS count FROM cves
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END
        """)
        kev_row        = await conn.fetchrow("SELECT COUNT(*) FROM cves WHERE is_kev = TRUE")
        top_rows       = await conn.fetch("""
            SELECT p.id, p.name, p.version, p.vendor,
                   p.cve_count, p.critical_count, p.last_synced_at
            FROM products p
            ORDER BY p.critical_count DESC, p.cve_count DESC
            LIMIT 10
        """)
        recent_rows    = await conn.fetch("""
            SELECT c.cve_id, c.severity, c.cvss_v3_score, c.epss_score, c.is_kev,
                   c.published_at,
                   c.raw_payload->'descriptions'->0->>'value' AS description
            FROM cves c
            ORDER BY c.published_at DESC NULLS LAST
            LIMIT 10
        """)
        epss_row       = await conn.fetchrow("""
            SELECT
                SUM(CASE WHEN epss_score >= 0.5 THEN 1 ELSE 0 END)                       AS high_epss,
                SUM(CASE WHEN epss_score >= 0.1 AND epss_score < 0.5 THEN 1 ELSE 0 END)  AS medium_epss,
                SUM(CASE WHEN epss_score <  0.1 THEN 1 ELSE 0 END)                       AS low_epss
            FROM cves WHERE epss_score IS NOT NULL
        """)
        prio_row       = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE priority_score >= 80)                          AS critical_priority,
                COUNT(*) FILTER (WHERE priority_score >= 60 AND priority_score < 80)  AS high_priority,
                COUNT(*) FILTER (WHERE priority_score >= 40 AND priority_score < 60)  AS medium_priority,
                COUNT(*) FILTER (WHERE priority_score <  40 OR  priority_score IS NULL) AS monitor
            FROM findings WHERE status = 'open'
        """)
        pcount_row     = await conn.fetchrow("SELECT COUNT(*) FROM products")

    result: dict[str, Any] = {
        "total_cves":            int(total_row[0]),
        "kev_count":             int(kev_row[0]),
        "product_count":         int(pcount_row[0]),
        "severity":              [dict(r) for r in severity_rows],
        "top_products":          [dict(r) for r in top_rows],
        "recent_cves":           [dict(r) for r in recent_rows],
        "epss_distribution":     dict(epss_row) if epss_row else {},
        "priority_distribution": dict(prio_row) if prio_row else {},
    }

    await redis.setex("dashboard:stats", _STATS_TTL, json.dumps(result, default=str))
    return result


@router.get("/timeline")
async def dashboard_timeline(
    pool: asyncpg.Pool = Depends(_get_pool),
    redis: Redis = Depends(_get_redis),
) -> list[dict]:
    cached = await redis.get("dashboard:timeline")
    if cached:
        return json.loads(cached)

    rows = await pool.fetch(
        """
        SELECT
            TO_CHAR(published_at, 'YYYY-MM')                          AS month,
            COUNT(*)                                                   AS total,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL')             AS critical,
            COUNT(*) FILTER (WHERE severity = 'HIGH')                 AS high,
            COUNT(*) FILTER (WHERE is_kev = TRUE)                     AS kev
        FROM cves
        WHERE published_at >= NOW() - INTERVAL '12 months'
        GROUP BY month
        ORDER BY month ASC
        """
    )
    result = [dict(r) for r in rows]
    await redis.setex("dashboard:timeline", _TIMELINE_TTL, json.dumps(result))
    return result


# ────────────────────────────────────────────────────── Dashboard B (SOC Triage)

# The four "panels" that compose the SOC analyst landing.
#
# 1. top_urgent — highest priority_score open items the analyst should
#    look at *now*. Combines findings (when present) with CVE-only entries
#    so the panel works even on cold-start (empty findings table).
# 2. new_exploitability — CVEs whose exploitability flag (PoC or Nuclei
#    template) flipped in the last N days. Drives the "patch before it
#    becomes KEV" workflow.
# 3. aging_kev — CVEs in CISA KEV with no remediation activity for >3d
#    (KEV SLA), prioritised by EPSS.
# 4. epss_hotlist — high-EPSS CVEs that are NOT (yet) in KEV. These are
#    the most likely *future* KEV entries — patching them is preventive.
#
# Single endpoint to avoid fan-out from the frontend.

_TRIAGE_TTL = 60  # seconds


@router.get("/triage")
async def dashboard_triage(
    pool: asyncpg.Pool = Depends(_get_pool),
    redis: Redis = Depends(_get_redis),
    limit_per_panel: int = 10,
    delta_days: int = 7,
    aging_kev_days: int = 3,
    epss_threshold: float = 0.9,
    keyword: str | None = None,
) -> dict[str, Any]:
    limit_per_panel = max(1, min(50, limit_per_panel))
    delta_days = max(1, min(365, delta_days))
    aging_kev_days = max(1, min(365, aging_kev_days))
    epss_threshold = max(0.0, min(1.0, epss_threshold))

    cache_key = (
        f"dashboard:triage:l{limit_per_panel}:dd{delta_days}:ak{aging_kev_days}"
        f":epss{epss_threshold:.2f}:k{(keyword or '').strip().lower()[:40]}"
    )
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    # Reusable expression — same shape as the one in /api/cves.
    priority_expr = """
        LEAST(100, GREATEST(0,
            ROUND(COALESCE(c.epss_score, 0) * 40)::int
            + CASE
                WHEN c.severity = 'CRITICAL' OR c.cvss_v3_score >= 9.0 THEN 25
                WHEN c.severity = 'HIGH'     OR c.cvss_v3_score >= 7.0 THEN 18
                WHEN c.severity = 'MEDIUM'   OR c.cvss_v3_score >= 4.0 THEN 10
                WHEN c.severity = 'LOW'
                  OR (c.cvss_v3_score IS NOT NULL AND c.cvss_v3_score > 0)
                  OR (c.cvss_v2_score IS NOT NULL AND c.cvss_v2_score > 0) THEN 4
                ELSE 0
              END
            + CASE WHEN c.is_kev THEN 25 ELSE 0 END
            + CASE
                WHEN c.published_at >= NOW() - INTERVAL '30 days'  THEN 10
                WHEN c.published_at >= NOW() - INTERVAL '90 days'  THEN 6
                WHEN c.published_at >= NOW() - INTERVAL '365 days' THEN 3
                ELSE 0
              END
            + CASE
                WHEN c.has_nuclei_template = TRUE THEN 8
                WHEN c.has_public_poc      = TRUE THEN 5
                ELSE 0
              END
        ))::int
    """

    # The keyword filter is intentionally light — applied to CVE ID only
    # so the index is used and the queries stay fast.
    keyword_clause = ""
    keyword_args: list[Any] = []
    if keyword:
        keyword_clause = " AND c.cve_id ILIKE $1 "
        keyword_args = [f"%{keyword.strip().upper()}%"]

    common_cols = """
        c.cve_id,
        c.severity,
        c.cvss_v3_score,
        c.cvss_v2_score,
        c.epss_score,
        c.epss_percentile,
        c.is_kev,
        c.kev_added_date,
        c.published_at,
        c.last_modified_at,
        c.has_public_poc,
        c.has_nuclei_template,
        c.exploitability_updated_at,
        c.raw_payload->'descriptions'->0->>'value' AS description
    """

    async with pool.acquire() as conn:
        # 1. top urgent — priority desc, all CVEs (works on cold-start)
        top_urgent_rows = await conn.fetch(
            f"""
            SELECT {common_cols},
                   {priority_expr} AS priority_score
            FROM cves c
            WHERE 1=1 {keyword_clause}
            ORDER BY {priority_expr} DESC NULLS LAST,
                     c.cvss_v3_score DESC NULLS LAST
            LIMIT {limit_per_panel}
            """,
            *keyword_args,
        )

        # 2. new exploitability changes — recent flip on PoC / Nuclei
        new_expl_rows = await conn.fetch(
            f"""
            SELECT {common_cols},
                   {priority_expr} AS priority_score
            FROM cves c
            WHERE c.exploitability_updated_at >= NOW() - INTERVAL '{delta_days} days'
              AND (c.has_public_poc = TRUE OR c.has_nuclei_template = TRUE)
              {keyword_clause}
            ORDER BY c.exploitability_updated_at DESC,
                     {priority_expr} DESC NULLS LAST
            LIMIT {limit_per_panel}
            """,
            *keyword_args,
        )

        # 3. aging KEV — KEV CVEs added more than `aging_kev_days` ago
        aging_kev_rows = await conn.fetch(
            f"""
            SELECT {common_cols},
                   {priority_expr} AS priority_score,
                   (CURRENT_DATE - c.kev_added_date) AS days_in_kev
            FROM cves c
            WHERE c.is_kev = TRUE
              AND (c.kev_added_date IS NULL
                   OR c.kev_added_date < CURRENT_DATE - INTERVAL '{aging_kev_days} days')
              {keyword_clause}
            ORDER BY c.epss_score DESC NULLS LAST,
                     c.cvss_v3_score DESC NULLS LAST
            LIMIT {limit_per_panel}
            """,
            *keyword_args,
        )

        # 4. EPSS hotlist — high probability, not in KEV yet.
        # Argument order MUST match positional placeholders:
        # keyword_args first (their placeholder is $1 inside keyword_clause),
        # then the EPSS threshold at the next index.
        threshold_clause_idx = len(keyword_args) + 1
        epss_rows = await conn.fetch(
            f"""
            SELECT {common_cols},
                   {priority_expr} AS priority_score
            FROM cves c
            WHERE c.epss_score >= ${threshold_clause_idx}
              AND c.is_kev = FALSE
              {keyword_clause}
            ORDER BY c.epss_score DESC NULLS LAST
            LIMIT {limit_per_panel}
            """,
            *keyword_args,
            epss_threshold,
        )

    def _alias(row: asyncpg.Record) -> dict[str, Any]:
        d = dict(row)
        # Frontend uses `in_cisa_kev` historically (Node legacy compat).
        if "is_kev" in d:
            d["in_cisa_kev"] = d.pop("is_kev")
        return d

    payload: dict[str, Any] = {
        "params": {
            "limit_per_panel":  limit_per_panel,
            "delta_days":       delta_days,
            "aging_kev_days":   aging_kev_days,
            "epss_threshold":   epss_threshold,
            "keyword":          keyword,
        },
        "top_urgent":          [_alias(r) for r in top_urgent_rows],
        "new_exploitability":  [_alias(r) for r in new_expl_rows],
        "aging_kev":           [_alias(r) for r in aging_kev_rows],
        "epss_hotlist":        [_alias(r) for r in epss_rows],
    }
    await redis.setex(cache_key, _TRIAGE_TTL, json.dumps(payload, default=str))
    return payload
