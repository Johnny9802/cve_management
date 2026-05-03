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
