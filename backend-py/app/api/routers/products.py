"""Products router — /api/products

Preserves Node.js API contract:
  - Response field `cpe_keyword` maps to DB column `normalized_cpe`
  - Sync state derived from sync_jobs table (no sync_* columns on products)
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.dependencies.auth import AuthUser, require_role
from app.services import audit

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/products", tags=["products"])

_WRITER = require_role("analyst")


# ── request / response models ────────────────────────────────────────────────

class ProductCreate(BaseModel):
    name: str
    version: str
    vendor: str | None = None
    cpe_keyword: str | None = None  # alias for normalized_cpe


class BulkProductCreate(BaseModel):
    products: list[ProductCreate] = Field(..., max_length=500)


# ── helpers ──────────────────────────────────────────────────────────────────

def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


async def _enqueue_sync(conn: asyncpg.Connection, product_id: int, priority: int) -> int | None:
    row = await conn.fetchrow(
        """
        INSERT INTO sync_jobs (job_type, target_id, priority)
        SELECT 'product_sync', $1::text, $2
        WHERE NOT EXISTS (
            SELECT 1 FROM sync_jobs
            WHERE job_type   = 'product_sync'
              AND target_id  = $1::text
              AND status IN ('pending', 'running')
        )
        RETURNING id
        """,
        str(product_id),
        priority,
    )
    return row["id"] if row else None


def _product_row(row: asyncpg.Record) -> dict[str, Any]:
    d = dict(row)
    d["cpe_keyword"] = d.pop("normalized_cpe", None)
    return d


# ── routes ────────────────────────────────────────────────────────────────────

@router.get("")
async def list_products(pool: asyncpg.Pool = Depends(_get_pool)) -> list[dict]:
    # Soft-delete (S4.6): the list endpoint never surfaces deleted
    # rows. Audit / governance reads them through audit_log instead.
    rows = await pool.fetch(
        """
        SELECT p.id, p.name, p.version, p.vendor,
               p.normalized_cpe, p.cpe_confidence,
               p.sync_status, p.last_synced_at,
               p.cve_count, p.critical_count,
               p.created_at, p.updated_at,
               j.id AS active_job_id, j.status AS job_status,
               j.attempts, j.scheduled_at AS job_scheduled_at
        FROM products p
        LEFT JOIN sync_jobs j
          ON j.target_id = p.id::text
         AND j.job_type  = 'product_sync'
         AND j.status IN ('pending', 'running')
        WHERE p.is_deleted = FALSE
        ORDER BY p.critical_count DESC, p.cve_count DESC, p.name ASC
        """
    )
    return [_product_row(r) for r in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_product(
    body: ProductCreate,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    user: AuthUser = Depends(_WRITER),
) -> dict:
    async with pool.acquire() as conn, conn.transaction():
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO products (name, version, vendor, normalized_cpe)
                VALUES ($1, $2, $3, $4)
                RETURNING *
                """,
                body.name.strip(),
                body.version.strip(),
                body.vendor.strip() if body.vendor else None,
                body.cpe_keyword.strip() if body.cpe_keyword else None,
            )
        except asyncpg.UniqueViolationError as err:
            raise HTTPException(status_code=409, detail="Product already exists") from err

        job_id = await _enqueue_sync(conn, row["id"], priority=10)

        await audit.record_in_tx(
            conn,
            action="product.create",
            target_type="product",
            target_id=str(row["id"]),
            actor_email=user.email,
            actor_role=user.role,
            diff={"after": _product_row(row)},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    result = _product_row(row)
    result["syncing"] = job_id is not None
    return result


@router.post("/bulk")
async def bulk_import(
    body: BulkProductCreate,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    user: AuthUser = Depends(_WRITER),
) -> dict:
    created, skipped, errors = [], [], []

    async with pool.acquire() as conn:
        for p in body.products:
            if not p.name or not p.version:
                errors.append({**p.model_dump(), "reason": "missing name or version"})
                continue
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO products (name, version, vendor, normalized_cpe)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (name, vendor, version) DO NOTHING
                    RETURNING *
                    """,
                    p.name.strip(),
                    p.version.strip(),
                    p.vendor.strip() if p.vendor else None,
                    p.cpe_keyword.strip() if p.cpe_keyword else None,
                )
                if row:
                    await _enqueue_sync(conn, row["id"], priority=50)
                    created.append(_product_row(row))
                else:
                    skipped.append(p.model_dump())
            except Exception as exc:
                errors.append({**p.model_dump(), "reason": str(exc)})

    # One audit row per import batch keeps the audit_log readable;
    # the diff carries counts so we can still trace what landed.
    await audit.record(
        pool,
        action="product.bulk_import",
        target_type="product",
        target_id=None,
        actor_email=user.email,
        actor_role=user.role,
        diff={
            "counts": {
                "created": len(created),
                "skipped": len(skipped),
                "errors": len(errors),
            }
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return {"created": created, "skipped": skipped, "errors": errors}


@router.post("/resync-all")
async def resync_all(
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    user: AuthUser = Depends(_WRITER),
) -> dict:
    rows = await pool.fetch("SELECT id, name, version FROM products ORDER BY name")
    if not rows:
        return {"message": "No products to sync", "count": 0}

    enqueued = 0
    async with pool.acquire() as conn:
        for r in rows:
            job_id = await _enqueue_sync(conn, r["id"], priority=100)
            if job_id:
                enqueued += 1

    await audit.record(
        pool,
        action="product.resync_all",
        target_type="product",
        target_id=None,
        actor_email=user.email,
        actor_role=user.role,
        diff={"counts": {"enqueued": enqueued, "total": len(rows)}},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return {
        "message": f"Enqueued {enqueued} product(s) for re-sync.",
        "count": enqueued,
        "total": len(rows),
    }


@router.delete("/{product_id}")
async def delete_product(
    product_id: int,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    user: AuthUser = Depends(_WRITER),
) -> dict:
    # Soft-delete (S4.6). The original cascade-DELETE wiped findings,
    # findings_history and risk_acceptances on every removal — losing
    # all the governance trail past the audit_log row. We now flip
    # ``is_deleted`` and stamp the actor; reads filter the column
    # away. Re-creating a (name, vendor, version) tuple is allowed
    # thanks to the partial UNIQUE introduced in alembic 0011.
    #
    # Findings linked to the product are nudged to ``closed`` (with a
    # history row) so the FSM contract stays consistent — they're no
    # longer actionable, but the audit timeline keeps them.
    async with pool.acquire() as conn, conn.transaction():
        snapshot = await conn.fetchrow(
            """
            SELECT id, name, vendor, version, cve_count, critical_count, is_deleted
            FROM products
            WHERE id = $1
            """,
            product_id,
        )
        if not snapshot:
            raise HTTPException(status_code=404, detail="Product not found")
        if snapshot["is_deleted"]:
            raise HTTPException(status_code=409, detail="Product already deleted")

        await conn.execute(
            """
            UPDATE products
            SET is_deleted = TRUE,
                deleted_at = NOW(),
                deleted_by = $2,
                updated_at = NOW()
            WHERE id = $1
            """,
            product_id,
            user.email,
        )

        # Mark open findings as ``closed`` with a history row so the
        # FSM stays auditable. Already-closed/remediated/etc are left
        # alone.
        affected = await conn.fetch(
            """
            UPDATE findings
            SET status = 'closed', updated_at = NOW()
            WHERE product_id = $1
              AND status NOT IN ('closed', 'remediated', 'false_positive')
            RETURNING id, status
            """,
            product_id,
        )
        for row in affected:
            await conn.execute(
                """
                INSERT INTO findings_history
                    (finding_id, old_status, new_status, changed_by, reason)
                VALUES ($1, 'open', 'closed', $2, 'product soft-deleted')
                """,
                row["id"],
                user.email,
            )

        await audit.record_in_tx(
            conn,
            action="product.delete",
            target_type="product",
            target_id=str(product_id),
            actor_email=user.email,
            actor_role=user.role,
            diff={
                "before": {k: v for k, v in dict(snapshot).items() if k != "is_deleted"},
                "after": {"is_deleted": True},
                "findings_closed": len(affected),
            },
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    from app.core.cache import delete_pattern
    await delete_pattern(request.app.state.redis, "dashboard:*")
    return {"deleted": True, "findings_closed": len(affected)}


@router.post("/{product_id}/sync")
async def manual_sync(
    product_id: int,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    user: AuthUser = Depends(_WRITER),
) -> dict:
    exists = await pool.fetchrow("SELECT id FROM products WHERE id = $1", product_id)
    if not exists:
        raise HTTPException(status_code=404, detail="Product not found")

    async with pool.acquire() as conn, conn.transaction():
        job_id = await _enqueue_sync(conn, product_id, priority=10)
        await audit.record_in_tx(
            conn,
            action="product.sync",
            target_type="product",
            target_id=str(product_id),
            actor_email=user.email,
            actor_role=user.role,
            diff={"job_id": job_id},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return {"syncing": True, "job_id": job_id}


@router.get("/{product_id}/sync-status")
async def sync_status(
    product_id: int,
    pool: asyncpg.Pool = Depends(_get_pool),
) -> dict:
    row = await pool.fetchrow(
        """
        SELECT p.sync_status, p.last_synced_at, p.cve_count, p.critical_count,
               j.id AS job_id, j.status AS job_status, j.attempts,
               j.scheduled_at, j.error_message
        FROM products p
        LEFT JOIN sync_jobs j
          ON j.target_id = p.id::text
         AND j.job_type  = 'product_sync'
         AND j.status IN ('pending', 'running')
        WHERE p.id = $1
        """,
        product_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")
    return dict(row)
