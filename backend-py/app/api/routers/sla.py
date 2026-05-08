"""SLA + MTTR endpoints (P8).

* ``GET /api/findings/sla?state=breached`` — list findings filtered by SLA state.
* ``GET /api/findings/sla/summary``        — counters per severity / state.
* ``GET /api/findings/mttr?period=90d``    — mean time to remediation, per severity.

These endpoints are read-only and rely on the ``findings.due_date`` column
plus the ``compute_sla_state`` helper from ``app.services.sla``. The
calculation runs in Python rather than via a materialized view to keep
the deployment simpler — the per-state counters are O(rows) and the
typical finding count is well within an in-memory pass.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request

from app.services.sla import (
    AT_RISK_THRESHOLD_DAYS,
    SLA_DAYS,
    SLA_KEV_OVERRIDE,
    compute_sla_state,
    days_overdue,
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/findings", tags=["sla"])

_VALID_STATES = {"on_track", "at_risk", "breached", "met"}
_REMEDIATED_STATUSES = ("remediated", "closed", "false_positive")


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


@router.get("/sla")
async def list_findings_by_sla(
    pool: asyncpg.Pool = Depends(_get_pool),
    state: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    if state is not None and state not in _VALID_STATES:
        raise HTTPException(
            422, f"invalid state '{state}', allowed: {sorted(_VALID_STATES)}"
        )
    limit = max(1, min(500, limit))

    rows = await pool.fetch(
        """
        SELECT
            f.id, f.product_id, f.cve_id, f.status, f.due_date,
            f.priority_score, f.created_at,
            c.severity, c.is_kev, c.published_at,
            p.name AS product_name, p.vendor, p.version
        FROM findings f
        JOIN cves     c ON c.cve_id     = f.cve_id
        JOIN products p ON p.id         = f.product_id
        ORDER BY f.due_date ASC NULLS LAST
        """,
    )

    today = datetime.now(tz=UTC).date()
    out: list[dict[str, Any]] = []
    for r in rows:
        sla_state = compute_sla_state(
            finding_status=r["status"],
            due_date=r["due_date"],
            today=today,
        )
        if state is not None and sla_state != state:
            continue
        out.append(
            {
                **dict(r),
                "sla_state": sla_state,
                "days_overdue": days_overdue(r["due_date"], today=today),
            }
        )
        if len(out) >= limit:
            break
    return {"data": out, "total": len(out), "filter_state": state}


@router.get("/sla/summary")
async def sla_summary(pool: asyncpg.Pool = Depends(_get_pool)) -> dict[str, Any]:
    """Counters per (severity, sla_state) for dashboards."""
    rows = await pool.fetch(
        """
        SELECT
            f.status,
            f.due_date,
            c.severity,
            c.is_kev
        FROM findings f
        JOIN cves c ON c.cve_id = f.cve_id
        """,
    )
    today = datetime.now(tz=UTC).date()

    counters: dict[str, dict[str, int]] = {}
    totals_by_state: dict[str, int] = {s: 0 for s in _VALID_STATES}
    kev_breached = 0

    for r in rows:
        severity = (r["severity"] or "UNKNOWN").upper()
        sla_state = compute_sla_state(
            finding_status=r["status"], due_date=r["due_date"], today=today
        )
        if severity not in counters:
            counters[severity] = {s: 0 for s in _VALID_STATES}
        counters[severity][sla_state] += 1
        totals_by_state[sla_state] += 1
        if sla_state == "breached" and r["is_kev"]:
            kev_breached += 1

    return {
        "matrix": SLA_DAYS,
        "kev_override_days": SLA_KEV_OVERRIDE,
        "at_risk_threshold_days": AT_RISK_THRESHOLD_DAYS,
        "by_severity": counters,
        "totals": totals_by_state,
        "kev_breached": kev_breached,
    }


@router.get("/mttr")
async def mttr(
    pool: asyncpg.Pool = Depends(_get_pool),
    period: str = "90d",
) -> dict[str, Any]:
    """Mean time to remediation per severity, in days, computed over
    findings remediated in the last ``period`` (e.g. ``90d`` / ``30d``).

    Sources `findings_history` for the moment of `remediated` transition,
    falling back to `findings.updated_at` if no history row matches.
    """
    days = _parse_period(period)
    cutoff = datetime.now(tz=UTC) - timedelta(days=days)

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
            f.id,
            f.created_at,
            COALESCE(lr.changed_at, f.updated_at) AS remediated_at,
            c.severity
        FROM findings f
        JOIN cves c ON c.cve_id = f.cve_id
        LEFT JOIN last_remediated lr ON lr.finding_id = f.id
        WHERE f.status = 'remediated'
          AND COALESCE(lr.changed_at, f.updated_at) >= $1
        """,
        cutoff,
    )

    by_sev: dict[str, list[float]] = {}
    for r in rows:
        sev = (r["severity"] or "UNKNOWN").upper()
        delta = (r["remediated_at"] - r["created_at"]).total_seconds() / 86400.0
        by_sev.setdefault(sev, []).append(delta)

    out = {
        sev: {
            "count": len(deltas),
            "mttr_days": round(sum(deltas) / len(deltas), 2) if deltas else 0,
            "p50_days": round(sorted(deltas)[len(deltas) // 2], 2) if deltas else 0,
        }
        for sev, deltas in by_sev.items()
    }
    return {"period_days": days, "by_severity": out}


def _parse_period(period: str) -> int:
    period = (period or "").strip().lower()
    if period.endswith("d") and period[:-1].isdigit():
        return max(1, int(period[:-1]))
    if period.isdigit():
        return max(1, int(period))
    raise HTTPException(422, f"invalid period: '{period}', expected '90d' or '30'")
