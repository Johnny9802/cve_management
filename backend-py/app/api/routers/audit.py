"""Read-only audit log endpoint (P9 partial).

Sprint 3 brief excludes RBAC; this endpoint is therefore exposed without
auth. **In production it MUST be put behind a network ACL or reverse-proxy
auth layer**, since the rows may contain sensitive operational signals
(actor identities, finding ids, masked secrets).
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/audit-log", tags=["audit"])


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


@router.get("")
async def list_audit_log(
    pool: asyncpg.Pool = Depends(_get_pool),
    target_type: str | None = None,
    target_id: str | None = None,
    action: str | None = None,
    actor_email: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise HTTPException(422, "limit must be between 1 and 500")

    rows = await pool.fetch(
        """
        SELECT id, action, actor, actor_email, actor_role,
               target_type, target_id,
               diff, metadata, ip_address, user_agent, ts
        FROM audit_log
        WHERE ($1::text IS NULL OR target_type = $1)
          AND ($2::text IS NULL OR target_id   = $2)
          AND ($3::text IS NULL OR action      = $3)
          AND ($4::text IS NULL OR actor_email = $4)
        ORDER BY ts DESC
        LIMIT $5
        """,
        target_type,
        target_id,
        action,
        actor_email,
        limit,
    )
    return {"data": [dict(r) for r in rows], "total": len(rows)}
