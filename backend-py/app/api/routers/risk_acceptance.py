"""Risk-acceptance workflow endpoints (P8).

Lifecycle:

  request → pending → approved → finding.status = accepted_risk
                    → rejected (terminal)
                    → expired (when expires_at passes; finding goes back to open)

The expire transition is driven by the daily ``expire_risk_acceptances``
APScheduler job, not by these endpoints.

OpSec / no-RBAC note
--------------------
The Sprint 3 brief excludes RBAC. We accept the requester / approver
identities as plain strings supplied by the API caller (or via an
optional ``X-Actor-Email`` header). In production these endpoints must
be put behind a reverse-proxy auth layer until proper auth is added.
"""
from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.api.dependencies.auth import AuthUser, require_role
from app.services.audit import record_in_tx

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/findings", tags=["risk-acceptance"])

_WRITER = require_role("analyst")


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


def _actor(request: Request) -> str:
    """Best-effort actor extraction. Falls back to anonymous."""
    return request.headers.get("X-Actor-Email", "anonymous")


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ─────────────────────────────────────────────────────── models


class RiskAcceptanceCreate(BaseModel):
    # ``requested_by`` is now ignored for authorization — the JWT
    # subject is authoritative — but we keep it in the contract so the
    # frontend can still send a free-form display name without
    # breaking. The audit row uses user.email.
    requested_by: str | None = Field(default=None, max_length=200)
    justification: str = Field(min_length=10, max_length=4000)
    expires_at: date

    @field_validator("expires_at")
    @classmethod
    def _future(cls, v: date) -> date:
        if v <= datetime.now(tz=UTC).date():
            raise ValueError("expires_at must be in the future")
        return v


class RiskAcceptanceDecision(BaseModel):
    action: str = Field(pattern="^(approve|reject)$")
    # ``decided_by`` ignored for authorization (JWT is authoritative);
    # kept optional for FE compatibility.
    decided_by: str | None = Field(default=None, max_length=200)
    note: str | None = Field(default=None, max_length=2000)


# ────────────────────────────────────────────────────── routes


@router.post("/{product_id}/{cve_id}/risk-acceptance")
async def create_risk_acceptance(
    product_id: int,
    cve_id: str,
    body: RiskAcceptanceCreate,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    user: AuthUser = Depends(_WRITER),
) -> dict[str, Any]:
    requested_by = user.email
    cve_id = cve_id.upper()
    async with pool.acquire() as conn:
        finding = await conn.fetchrow(
            "SELECT id, status FROM findings WHERE product_id = $1 AND cve_id = $2",
            product_id,
            cve_id,
        )
        if finding is None:
            raise HTTPException(404, "finding not found")
        if finding["status"] in {"remediated", "closed", "false_positive"}:
            raise HTTPException(
                409,
                f"cannot request risk acceptance for finding in status '{finding['status']}'",
            )

        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO risk_acceptances
                    (finding_id, requested_by, justification, expires_at, status)
                VALUES ($1, $2, $3, $4, 'pending')
                RETURNING *
                """,
                finding["id"],
                requested_by,
                body.justification,
                body.expires_at,
            )
            await record_in_tx(
                conn,
                action="risk_acceptance.request",
                target_type="finding",
                target_id=f"{product_id}:{cve_id}",
                actor_email=requested_by,
                actor_role=user.role,
                diff={
                    "after": {
                        "status": "pending",
                        "expires_at": body.expires_at.isoformat(),
                        "justification_len": len(body.justification),
                    }
                },
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
    return dict(row) if row else {}


@router.patch("/{product_id}/{cve_id}/risk-acceptance/{acceptance_id}")
async def decide_risk_acceptance(
    product_id: int,
    cve_id: str,
    acceptance_id: int,
    body: RiskAcceptanceDecision,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    user: AuthUser = Depends(_WRITER),
) -> dict[str, Any]:
    cve_id = cve_id.upper()
    decided_by = user.email
    new_status = "approved" if body.action == "approve" else "rejected"

    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            """
            SELECT ra.*, f.product_id, f.cve_id
            FROM risk_acceptances ra
            JOIN findings f ON f.id = ra.finding_id
            WHERE ra.id = $1
              AND f.product_id = $2
              AND f.cve_id = $3
            """,
            acceptance_id,
            product_id,
            cve_id,
        )
        if existing is None:
            raise HTTPException(404, "risk acceptance not found")
        if existing["status"] != "pending":
            raise HTTPException(
                409, f"already decided (status={existing['status']})"
            )
        if new_status == "approved" and existing["requested_by"] == decided_by:
            raise HTTPException(
                409, "approver must differ from requester (segregation of duties)"
            )

        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE risk_acceptances
                SET status      = $2,
                    approved_by = $3,
                    decided_at  = NOW()
                WHERE id = $1
                RETURNING *
                """,
                acceptance_id,
                new_status,
                decided_by,
            )
            if new_status == "approved":
                await conn.execute(
                    """
                    UPDATE findings
                    SET status     = 'accepted_risk',
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    existing["finding_id"],
                )
                await conn.execute(
                    """
                    INSERT INTO findings_history
                        (finding_id, old_status, new_status, changed_by, reason)
                    VALUES ($1, $2, 'accepted_risk', $3, $4)
                    """,
                    existing["finding_id"],
                    "open",
                    decided_by,
                    f"risk_acceptance.approve#{acceptance_id}",
                )
            await record_in_tx(
                conn,
                action=f"risk_acceptance.{body.action}",
                target_type="risk_acceptance",
                target_id=str(acceptance_id),
                actor_email=decided_by,
                actor_role="approver",
                diff={
                    "before": {"status": "pending"},
                    "after": {"status": new_status, "note": body.note},
                },
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
    return dict(row) if row else {}


@router.get("/{product_id}/{cve_id}/risk-acceptance")
async def list_finding_risk_acceptances(
    product_id: int,
    cve_id: str,
    pool: asyncpg.Pool = Depends(_get_pool),
) -> dict[str, Any]:
    cve_id = cve_id.upper()
    rows = await pool.fetch(
        """
        SELECT ra.*
        FROM risk_acceptances ra
        JOIN findings f ON f.id = ra.finding_id
        WHERE f.product_id = $1 AND f.cve_id = $2
        ORDER BY ra.created_at DESC
        """,
        product_id,
        cve_id,
    )
    return {"data": [dict(r) for r in rows], "total": len(rows)}


# ─────────────────────────────────────────────────── separate top-level routes


_risk_summary_router = APIRouter(prefix="/api/risk-acceptances", tags=["risk-acceptance"])


@_risk_summary_router.get("/summary")
async def risk_acceptance_summary(
    pool: asyncpg.Pool = Depends(_get_pool),
    expiring_window_days: int = 7,
) -> dict[str, Any]:
    """Dashboard counters: pending / approved / rejected / expired
    plus a derived ``expiring_soon`` bucket of approved acceptances
    whose ``expires_at`` is within the next ``expiring_window_days``.
    """
    expiring_window_days = max(1, min(365, expiring_window_days))
    row = await pool.fetchrow(
        """
        SELECT
            COUNT(*) FILTER (WHERE status = 'pending')                               AS pending,
            COUNT(*) FILTER (WHERE status = 'approved')                              AS approved,
            COUNT(*) FILTER (WHERE status = 'rejected')                              AS rejected,
            COUNT(*) FILTER (WHERE status = 'expired')                               AS expired,
            COUNT(*) FILTER (
                WHERE status = 'approved'
                  AND expires_at <= CURRENT_DATE + ($1 || ' days')::interval
            )                                                                        AS expiring_soon,
            COUNT(*)                                                                  AS total
        FROM risk_acceptances
        """,
        str(expiring_window_days),
    )

    pending_recent = await pool.fetch(
        """
        SELECT ra.id, ra.finding_id, ra.requested_by, ra.justification,
               ra.expires_at, ra.created_at,
               f.product_id, f.cve_id, p.name AS product_name, p.version,
               c.severity
        FROM risk_acceptances ra
        JOIN findings f  ON f.id = ra.finding_id
        JOIN products p  ON p.id = f.product_id
        JOIN cves     c  ON c.cve_id = f.cve_id
        WHERE ra.status = 'pending'
        ORDER BY ra.created_at DESC
        LIMIT 10
        """,
    )

    expiring_rows = await pool.fetch(
        """
        SELECT ra.id, ra.finding_id, ra.approved_by, ra.expires_at,
               (ra.expires_at - CURRENT_DATE) AS days_remaining,
               f.product_id, f.cve_id, p.name AS product_name, p.version,
               c.severity
        FROM risk_acceptances ra
        JOIN findings f  ON f.id = ra.finding_id
        JOIN products p  ON p.id = f.product_id
        JOIN cves     c  ON c.cve_id = f.cve_id
        WHERE ra.status = 'approved'
          AND ra.expires_at <= CURRENT_DATE + ($1 || ' days')::interval
        ORDER BY ra.expires_at ASC
        LIMIT 20
        """,
        str(expiring_window_days),
    )

    return {
        "expiring_window_days": expiring_window_days,
        "counters": dict(row) if row else {},
        "pending_recent":   [dict(r) for r in pending_recent],
        "expiring_soon":    [dict(r) for r in expiring_rows],
    }


# Mount the standalone summary router. The original prefix is
# ``/api/findings/...`` so a separate router is necessary for the
# /api/risk-acceptances family.
router_summary = _risk_summary_router
