"""Findings router — /api/findings

Lifecycle FSM: open → in_review → remediated | false_positive | accepted_risk | closed
Audit trail written to findings_history on every status change.

Sprint 3 additions:
  * Status changes also write to ``audit_log`` via the audit service so
    the application-level history is a superset of finding lifecycle
    events.
"""
from __future__ import annotations

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.services.audit import record_in_tx

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/findings", tags=["findings"])

_VALID_STATUSES = {"open", "in_review", "false_positive", "accepted_risk", "planned", "remediated", "closed"}

_HISTORY_SQL = """
    INSERT INTO findings_history (finding_id, old_status, new_status, changed_by, reason)
    VALUES ($1, $2, $3, $4, $5)
"""

_UPDATE_SQL = """
    UPDATE findings
    SET status      = COALESCE($2, status),
        assigned_to = COALESCE($3, assigned_to),
        due_date    = COALESCE($4, due_date),
        notes       = COALESCE($5, notes),
        updated_at  = NOW()
    WHERE product_id = $1 AND cve_id = $6
    RETURNING *
"""


class FindingUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    due_date: str | None = None
    notes: str | None = None
    actor: str | None = None
    reason: str | None = None


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


# ── routes ────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def finding_stats(pool: asyncpg.Pool = Depends(_get_pool)) -> dict:
    row = await pool.fetchrow(
        """
        SELECT
            COUNT(*) FILTER (WHERE status = 'open')           AS open_count,
            COUNT(*) FILTER (WHERE status = 'in_review')      AS in_review_count,
            COUNT(*) FILTER (WHERE status = 'remediated')     AS remediated_count,
            COUNT(*) FILTER (WHERE status = 'false_positive') AS false_positive_count,
            COUNT(*) FILTER (WHERE status = 'accepted_risk')  AS accepted_risk_count,
            COUNT(*)                                           AS total
        FROM findings
        """
    )
    return dict(row) if row else {}


@router.get("")
async def list_findings(
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    status: str | None = None,
    owner: str | None = None,
    page: int = 1,
    limit: int = 50,
) -> dict:
    limit = min(200, max(1, limit))
    offset = (page - 1) * limit

    rows = await pool.fetch(
        """
        SELECT f.id, f.product_id, f.cve_id, f.status, f.match_confidence,
               f.priority_score, f.assigned_to, f.due_date, f.notes,
               f.created_at, f.updated_at,
               c.severity, c.cvss_v3_score, c.epss_score, c.is_kev,
               c.raw_payload->'descriptions'->0->>'value' AS description,
               p.name AS product_name, p.version AS product_version
        FROM findings f
        JOIN cves     c ON c.cve_id     = f.cve_id
        JOIN products p ON p.id         = f.product_id
        WHERE ($1::text IS NULL OR f.status      = $1)
          AND ($2::text IS NULL OR f.assigned_to = $2)
        ORDER BY f.priority_score DESC NULLS LAST, c.cvss_v3_score DESC NULLS LAST
        LIMIT $3 OFFSET $4
        """,
        status, owner, limit, offset,
    )
    total_row = await pool.fetchrow(
        """
        SELECT COUNT(*) FROM findings f
        WHERE ($1::text IS NULL OR f.status = $1)
          AND ($2::text IS NULL OR f.assigned_to = $2)
        """,
        status, owner,
    )
    return {
        "data": [dict(r) for r in rows],
        "total": int(total_row[0]) if total_row else 0,
        "page": page,
        "limit": limit,
    }


@router.patch("/{product_id}/{cve_id}")
async def update_finding(
    product_id: int,
    cve_id: str,
    body: FindingUpdate,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
) -> dict:
    cve_id = cve_id.upper()

    if body.status and body.status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{body.status}'. Valid: {sorted(_VALID_STATUSES)}",
        )

    async with pool.acquire() as conn:
        current = await conn.fetchrow(
            "SELECT id, status FROM findings WHERE product_id = $1 AND cve_id = $2",
            product_id, cve_id,
        )
        if not current:
            raise HTTPException(status_code=404, detail="Finding not found")

        due_date = None
        if body.due_date:
            from datetime import date
            try:
                due_date = date.fromisoformat(body.due_date)
            except ValueError:
                raise HTTPException(status_code=422, detail="due_date must be YYYY-MM-DD")

        async with conn.transaction():
            row = await conn.fetchrow(
                _UPDATE_SQL,
                product_id, body.status, body.assigned_to,
                due_date, body.notes, cve_id,
            )
            status_changed = body.status and body.status != current["status"]
            if status_changed:
                await conn.execute(
                    _HISTORY_SQL,
                    current["id"],
                    current["status"],
                    body.status,
                    body.actor or "api",
                    body.reason,
                )
            # P9 — application-level audit log entry, atomic with the
            # update / history rows above. Never written if the
            # transaction rolls back.
            await record_in_tx(
                conn,
                action=(
                    "finding.status_change" if status_changed else "finding.update"
                ),
                target_type="finding",
                target_id=f"{product_id}:{cve_id}",
                actor_email=body.actor,
                actor_role="analyst",
                diff={
                    "before": {
                        "status": current["status"],
                    },
                    "after": {
                        "status": body.status or current["status"],
                        "assigned_to": body.assigned_to,
                        "due_date": str(due_date) if due_date else None,
                        "reason": body.reason,
                    },
                },
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )

    from app.core.cache import delete_pattern
    await delete_pattern(request.app.state.redis, "dashboard:*")
    return dict(row) if row else {}


@router.get("/{product_id}/{cve_id}/history")
async def finding_history(
    product_id: int,
    cve_id: str,
    pool: asyncpg.Pool = Depends(_get_pool),
) -> list[dict]:
    cve_id = cve_id.upper()
    rows = await pool.fetch(
        """
        SELECT h.id, h.old_status, h.new_status, h.changed_by, h.changed_at, h.reason
        FROM findings_history h
        JOIN findings f ON f.id = h.finding_id
        WHERE f.product_id = $1 AND f.cve_id = $2
        ORDER BY h.changed_at DESC
        """,
        product_id, cve_id,
    )
    return [dict(r) for r in rows]
