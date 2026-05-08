"""Daily ``expire_risk_acceptances`` job (P8).

Walks every approved risk acceptance whose ``expires_at`` is past,
flips its status to ``expired``, reopens the underlying finding if it is
still in ``accepted_risk``, writes a ``findings_history`` row and an
``audit_log`` row. Runs in a single transaction per acceptance to keep
the audit atomic with the state change.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import asyncpg
import structlog

from app.services.audit import record_in_tx

logger = structlog.get_logger(__name__)


@dataclass
class ExpireResult:
    job: str
    expired: int
    reopened: int
    duration_ms: int


_FETCH_DUE_SQL = """
    SELECT ra.id, ra.finding_id, f.product_id, f.cve_id, f.status
    FROM risk_acceptances ra
    JOIN findings f ON f.id = ra.finding_id
    WHERE ra.status = 'approved'
      AND ra.expires_at < CURRENT_DATE
    FOR UPDATE OF ra SKIP LOCKED
"""


async def expire_risk_acceptances(pool: asyncpg.Pool) -> ExpireResult:
    t0 = time.monotonic()
    expired = 0
    reopened = 0

    async with pool.acquire() as conn, conn.transaction():
        due = await conn.fetch(_FETCH_DUE_SQL)
        for r in due:
            await conn.execute(
                "UPDATE risk_acceptances SET status='expired' WHERE id=$1",
                r["id"],
            )
            expired += 1

            if r["status"] == "accepted_risk":
                await conn.execute(
                    "UPDATE findings SET status='open', updated_at=NOW() WHERE id=$1",
                    r["finding_id"],
                )
                await conn.execute(
                    """
                        INSERT INTO findings_history
                            (finding_id, old_status, new_status, changed_by, reason)
                        VALUES ($1, 'accepted_risk', 'open', 'system', $2)
                        """,
                    r["finding_id"],
                    f"risk_acceptance.expire#{r['id']}",
                )
                reopened += 1

            await record_in_tx(
                conn,
                action="risk_acceptance.expire",
                target_type="risk_acceptance",
                target_id=str(r["id"]),
                actor_email="system",
                actor_role="system",
                diff={
                    "before": {"status": "approved"},
                    "after": {"status": "expired"},
                    "finding": {
                        "product_id": r["product_id"],
                        "cve_id": r["cve_id"],
                        "reopened": r["status"] == "accepted_risk",
                    },
                },
            )

    duration_ms = int((time.monotonic() - t0) * 1000)
    if expired:
        logger.info(
            "risk_acceptance.expire.done",
            expired=expired,
            reopened=reopened,
            duration_ms=duration_ms,
        )
    return ExpireResult(
        job="expire_risk_acceptances",
        expired=expired,
        reopened=reopened,
        duration_ms=duration_ms,
    )
