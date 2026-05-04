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


# ───────────────────────────────────────────── Dashboard D (Remediation)

_REMEDIATION_TTL = 30  # seconds — kanban must feel fresh after status change


@router.get("/owner-workload")
async def dashboard_owner_workload(
    pool: asyncpg.Pool = Depends(_get_pool),
) -> dict[str, Any]:
    """Per-owner aggregates for the Remediation dashboard.

    Returns one row per assignee with counts of open / in_review /
    breached (open and past due) / remediated and the average days
    between creation and the latest 'remediated' history entry.
    Findings without an assignee are grouped under ``unassigned``.
    """
    rows = await pool.fetch(
        """
        WITH last_remediated AS (
            SELECT DISTINCT ON (finding_id)
                   finding_id, changed_at
            FROM findings_history
            WHERE new_status = 'remediated'
            ORDER BY finding_id, changed_at DESC
        )
        SELECT
            COALESCE(NULLIF(TRIM(f.assigned_to), ''), 'unassigned') AS owner,
            COUNT(*)                                                AS total,
            COUNT(*) FILTER (WHERE f.status = 'open')               AS open_count,
            COUNT(*) FILTER (WHERE f.status = 'in_review')          AS in_review_count,
            COUNT(*) FILTER (WHERE f.status = 'planned')            AS planned_count,
            COUNT(*) FILTER (WHERE f.status = 'accepted_risk')      AS accepted_risk_count,
            COUNT(*) FILTER (WHERE f.status = 'remediated')         AS remediated_count,
            COUNT(*) FILTER (WHERE f.status = 'closed')             AS closed_count,
            COUNT(*) FILTER (
                WHERE f.status IN ('open', 'in_review', 'planned')
                  AND f.due_date IS NOT NULL
                  AND f.due_date < CURRENT_DATE
            )                                                       AS breached_count,
            ROUND(
              AVG(
                EXTRACT(EPOCH FROM (COALESCE(lr.changed_at, f.updated_at) - f.created_at))
                / 86400.0
              ) FILTER (WHERE f.status = 'remediated')::numeric,
              1
            )                                                       AS avg_days_to_remediate
        FROM findings f
        LEFT JOIN last_remediated lr ON lr.finding_id = f.id
        GROUP BY owner
        ORDER BY breached_count DESC, open_count DESC, owner ASC
        """
    )
    return {"owners": [dict(r) for r in rows], "total_owners": len(rows)}


@router.get("/remediation")
async def dashboard_remediation(
    pool: asyncpg.Pool = Depends(_get_pool),
    redis: Redis = Depends(_get_redis),
    audit_limit: int = 30,
) -> dict[str, Any]:
    """Consolidated payload for Dashboard D so the page does ONE call.

    Pulls in: pipeline counts (FSM kanban), SLA matrix, MTTR per
    severity (90d), risk-acceptance summary, owner workload, and the
    last N audit-log entries.
    """
    audit_limit = max(1, min(200, audit_limit))
    cache_key = f"dashboard:remediation:al{audit_limit}"
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    async with pool.acquire() as conn:
        pipeline_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'open')           AS open_count,
                COUNT(*) FILTER (WHERE status = 'in_review')      AS in_review_count,
                COUNT(*) FILTER (WHERE status = 'planned')        AS planned_count,
                COUNT(*) FILTER (WHERE status = 'accepted_risk')  AS accepted_risk_count,
                COUNT(*) FILTER (WHERE status = 'remediated')     AS remediated_count,
                COUNT(*) FILTER (WHERE status = 'closed')         AS closed_count,
                COUNT(*) FILTER (WHERE status = 'false_positive') AS false_positive_count,
                COUNT(*)                                           AS total
            FROM findings
            """,
        )

        sla_rows = await conn.fetch(
            """
            SELECT
                f.id, f.product_id, f.cve_id, f.status, f.due_date, f.assigned_to,
                f.priority_score, c.severity, c.is_kev,
                p.name AS product_name, p.version
            FROM findings f
            JOIN cves c     ON c.cve_id = f.cve_id
            JOIN products p ON p.id     = f.product_id
            ORDER BY f.due_date ASC NULLS LAST
            LIMIT 200
            """,
        )

        risk_summary_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending')                               AS pending,
                COUNT(*) FILTER (WHERE status = 'approved')                              AS approved,
                COUNT(*) FILTER (WHERE status = 'rejected')                              AS rejected,
                COUNT(*) FILTER (WHERE status = 'expired')                               AS expired,
                COUNT(*) FILTER (
                    WHERE status = 'approved'
                      AND expires_at <= CURRENT_DATE + INTERVAL '7 days'
                )                                                                        AS expiring_soon
            FROM risk_acceptances
            """,
        )

        audit_rows = await conn.fetch(
            """
            SELECT id, action, actor, actor_email, actor_role,
                   target_type, target_id, diff, ip_address, ts
            FROM audit_log
            ORDER BY ts DESC
            LIMIT $1
            """,
            audit_limit,
        )

    return_payload: dict[str, Any] = {
        "pipeline":       dict(pipeline_row) if pipeline_row else {},
        "findings":       [dict(r) for r in sla_rows],
        "risk_summary":   dict(risk_summary_row) if risk_summary_row else {},
        "audit_recent":   [dict(r) for r in audit_rows],
    }
    await redis.setex(cache_key, _REMEDIATION_TTL, json.dumps(return_payload, default=str))
    return return_payload


# ─────────────────────────────────────────────── Dashboard C (Asset Exposure)

_EXPOSURE_TTL = 300  # 5 min — exposure shifts slowly


@router.get("/exposure")
async def dashboard_exposure(
    pool: asyncpg.Pool = Depends(_get_pool),
    redis: Redis = Depends(_get_redis),
    top_limit: int = 10,
) -> dict[str, Any]:
    """Asset & product exposure aggregator (Dashboard C).

    Returns:
      - top_vendors: vendors ranked by total exposure (priority-weighted)
      - top_products_by_kev / top_products_by_critical
      - heatmap: top products × severity counts + KEV cell
      - inventory_coverage: % of products with resolved CPE / synced state
      - eol_candidates: products with critical findings AND no recent CVE
        publication (proxy for "no upstream patch in sight").
    """
    top_limit = max(1, min(50, top_limit))
    cache_key = f"dashboard:exposure:l{top_limit}"
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    async with pool.acquire() as conn:
        coverage_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*)                                                                 AS total,
                COUNT(*) FILTER (WHERE normalized_cpe IS NOT NULL AND normalized_cpe <> '') AS resolved,
                COUNT(*) FILTER (WHERE cpe_confidence = 'certain')                       AS confidence_certain,
                COUNT(*) FILTER (WHERE cpe_confidence = 'uncertain')                     AS confidence_uncertain,
                COUNT(*) FILTER (WHERE sync_status = 'synced')                           AS synced,
                COUNT(*) FILTER (WHERE sync_status = 'pending')                          AS pending,
                COUNT(*) FILTER (WHERE sync_status = 'error')                            AS sync_error,
                COUNT(*) FILTER (
                    WHERE last_synced_at IS NULL
                       OR last_synced_at < NOW() - INTERVAL '7 days'
                )                                                                        AS sync_stale
            FROM products
            """
        )

        top_vendors_rows = await conn.fetch(
            """
            SELECT
                COALESCE(NULLIF(TRIM(p.vendor), ''), '(unknown)')                       AS vendor,
                COUNT(DISTINCT p.id)                                                     AS product_count,
                COUNT(f.id)                                                              AS finding_count,
                COUNT(f.id) FILTER (WHERE c.severity = 'CRITICAL')                       AS critical_count,
                COUNT(f.id) FILTER (WHERE c.severity = 'HIGH')                           AS high_count,
                COUNT(f.id) FILTER (WHERE c.is_kev = TRUE)                               AS kev_count,
                COUNT(f.id) FILTER (WHERE c.has_public_poc = TRUE)                       AS poc_count,
                COUNT(f.id) FILTER (WHERE c.has_nuclei_template = TRUE)                  AS nuclei_count,
                COALESCE(SUM(f.priority_score) FILTER (
                    WHERE f.status IN ('open', 'in_review', 'planned')
                ), 0)                                                                    AS exposure_score
            FROM products p
            LEFT JOIN findings f ON f.product_id = p.id
            LEFT JOIN cves     c ON c.cve_id     = f.cve_id
            GROUP BY vendor
            ORDER BY exposure_score DESC, finding_count DESC, product_count DESC
            LIMIT $1
            """,
            top_limit,
        )

        top_products_kev = await conn.fetch(
            """
            SELECT
                p.id, p.name, p.version, p.vendor,
                COUNT(f.id)                                                              AS finding_count,
                COUNT(f.id) FILTER (WHERE c.is_kev = TRUE)                               AS kev_count,
                COUNT(f.id) FILTER (WHERE c.severity = 'CRITICAL')                       AS critical_count
            FROM products p
            LEFT JOIN findings f ON f.product_id = p.id
            LEFT JOIN cves     c ON c.cve_id     = f.cve_id
            GROUP BY p.id
            HAVING COUNT(f.id) FILTER (WHERE c.is_kev = TRUE) > 0
            ORDER BY kev_count DESC, critical_count DESC
            LIMIT $1
            """,
            top_limit,
        )

        top_products_critical = await conn.fetch(
            """
            SELECT
                p.id, p.name, p.version, p.vendor,
                COUNT(f.id)                                                              AS finding_count,
                COUNT(f.id) FILTER (WHERE c.is_kev = TRUE)                               AS kev_count,
                COUNT(f.id) FILTER (WHERE c.severity = 'CRITICAL')                       AS critical_count
            FROM products p
            LEFT JOIN findings f ON f.product_id = p.id
            LEFT JOIN cves     c ON c.cve_id     = f.cve_id
            GROUP BY p.id
            HAVING COUNT(f.id) FILTER (WHERE c.severity = 'CRITICAL') > 0
            ORDER BY critical_count DESC, finding_count DESC
            LIMIT $1
            """,
            top_limit,
        )

        heatmap_rows = await conn.fetch(
            """
            WITH ranked AS (
                SELECT p.id, p.name, p.version, p.vendor,
                       COUNT(f.id) AS findings
                FROM products p
                LEFT JOIN findings f ON f.product_id = p.id
                GROUP BY p.id
                ORDER BY findings DESC
                LIMIT $1
            )
            SELECT
                r.id, r.name, r.version, r.vendor,
                COUNT(f.id) FILTER (WHERE c.severity = 'CRITICAL')             AS critical,
                COUNT(f.id) FILTER (WHERE c.severity = 'HIGH')                 AS high,
                COUNT(f.id) FILTER (WHERE c.severity = 'MEDIUM')               AS medium,
                COUNT(f.id) FILTER (WHERE c.severity = 'LOW')                  AS low,
                COUNT(f.id) FILTER (WHERE c.is_kev = TRUE)                     AS kev,
                COUNT(f.id)                                                     AS total,
                ROUND(AVG(f.priority_score)::numeric, 1)                        AS avg_priority
            FROM ranked r
            LEFT JOIN findings f ON f.product_id = r.id
            LEFT JOIN cves     c ON c.cve_id     = f.cve_id
            GROUP BY r.id, r.name, r.version, r.vendor
            ORDER BY total DESC
            """,
            top_limit,
        )

        eol_rows = await conn.fetch(
            """
            SELECT
                p.id, p.name, p.version, p.vendor,
                COUNT(f.id)                                                       AS finding_count,
                COUNT(f.id) FILTER (WHERE c.severity = 'CRITICAL')                AS critical_count,
                MAX(c.last_modified_at)                                           AS last_cve_modified
            FROM products p
            JOIN findings f ON f.product_id = p.id
            JOIN cves     c ON c.cve_id     = f.cve_id
            GROUP BY p.id
            HAVING
                COUNT(f.id) FILTER (WHERE c.severity = 'CRITICAL') > 0
                AND MAX(c.last_modified_at) < NOW() - INTERVAL '365 days'
            ORDER BY critical_count DESC, last_cve_modified ASC
            LIMIT $1
            """,
            top_limit,
        )

    payload: dict[str, Any] = {
        "top_limit":              top_limit,
        "inventory_coverage":     dict(coverage_row) if coverage_row else {},
        "top_vendors":            [dict(r) for r in top_vendors_rows],
        "top_products_by_kev":    [dict(r) for r in top_products_kev],
        "top_products_by_critical": [dict(r) for r in top_products_critical],
        "heatmap":                [dict(r) for r in heatmap_rows],
        "eol_candidates":         [dict(r) for r in eol_rows],
    }
    await redis.setex(cache_key, _EXPOSURE_TTL, json.dumps(payload, default=str))
    return payload


# ───────────────────────────────────────────── Dashboard A (Executive)

_EXEC_TTL = 60


@router.get("/exec")
async def dashboard_exec(
    pool: asyncpg.Pool = Depends(_get_pool),
    redis: Redis = Depends(_get_redis),
    period_days: int = 90,
) -> dict[str, Any]:
    """Executive dashboard payload — trend lines from exec_snapshots."""
    period_days = max(7, min(730, period_days))
    cache_key = f"dashboard:exec:p{period_days}"
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    async with pool.acquire() as conn:
        snapshots = await conn.fetch(
            """
            SELECT
                captured_on, total_cves, kev_total,
                critical_open, high_open, medium_open, low_open,
                findings_open, findings_in_review, findings_remediated_24h,
                findings_breached, findings_at_risk,
                risk_pending, risk_approved, risk_expiring_soon,
                mttr_critical_days, mttr_high_days, mttr_medium_days, mttr_low_days,
                kev_with_open_finding, poc_with_open_finding, nuclei_with_open_finding,
                risk_score
            FROM exec_snapshots
            WHERE captured_on >= CURRENT_DATE - ($1 || ' days')::interval
            ORDER BY captured_on ASC
            """,
            str(period_days),
        )
        aging_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (
                    WHERE status IN ('open', 'in_review', 'planned')
                      AND created_at >= NOW() - INTERVAL '30 days'
                ) AS bucket_0_30,
                COUNT(*) FILTER (
                    WHERE status IN ('open', 'in_review', 'planned')
                      AND created_at <  NOW() - INTERVAL '30 days'
                      AND created_at >= NOW() - INTERVAL '90 days'
                ) AS bucket_30_90,
                COUNT(*) FILTER (
                    WHERE status IN ('open', 'in_review', 'planned')
                      AND created_at < NOW() - INTERVAL '90 days'
                ) AS bucket_90_plus,
                COUNT(*) FILTER (
                    WHERE status IN ('open', 'in_review', 'planned')
                ) AS open_total
            FROM findings
            """
        )
        velocity_rows = await conn.fetch(
            """
            SELECT
                TO_CHAR(date_trunc('week', changed_at), 'YYYY-MM-DD') AS week,
                COUNT(*) AS remediated_count
            FROM findings_history
            WHERE new_status = 'remediated'
              AND changed_at >= NOW() - INTERVAL '12 weeks'
            GROUP BY week
            ORDER BY week ASC
            """
        )
        top_owners_rows = await conn.fetch(
            """
            SELECT
                COALESCE(NULLIF(TRIM(f.assigned_to), ''), 'unassigned') AS owner,
                COUNT(*) FILTER (WHERE f.status = 'remediated')         AS remediated,
                COUNT(*) FILTER (
                    WHERE f.status IN ('open', 'in_review', 'planned')
                      AND f.due_date IS NOT NULL
                      AND f.due_date < CURRENT_DATE
                )                                                        AS breached,
                COUNT(*)                                                 AS total
            FROM findings f
            WHERE f.updated_at >= NOW() - INTERVAL '90 days'
              OR f.status IN ('open', 'in_review', 'planned')
            GROUP BY owner
            ORDER BY remediated DESC, breached ASC
            LIMIT 10
            """
        )

    series = [dict(r) for r in snapshots]
    latest = series[-1] if series else None
    earliest = series[0] if series else None

    def _delta(field: str) -> int | None:
        if latest is None or earliest is None:
            return None
        l, e = latest.get(field), earliest.get(field)
        if l is None or e is None:
            return None
        try:
            return int(l) - int(e)
        except (TypeError, ValueError):
            return None

    payload: dict[str, Any] = {
        "period_days":      period_days,
        "snapshots":        series,
        "latest":           latest,
        "earliest":         earliest,
        "deltas": {
            "risk_score":            _delta("risk_score"),
            "kev_with_open_finding": _delta("kev_with_open_finding"),
            "findings_open":         _delta("findings_open"),
            "findings_breached":     _delta("findings_breached"),
        },
        "aging_buckets":    dict(aging_row) if aging_row else {},
        "velocity_weekly":  [dict(r) for r in velocity_rows],
        "top_owners":       [dict(r) for r in top_owners_rows],
    }
    await redis.setex(cache_key, _EXEC_TTL, json.dumps(payload, default=str))
    return payload
