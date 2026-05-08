"""Webhook CRUD + test + deliveries (P7).

Endpoints
---------
* ``POST   /api/webhooks``                 — register
* ``GET    /api/webhooks``                 — list
* ``GET    /api/webhooks/{id}``            — fetch
* ``PATCH  /api/webhooks/{id}``            — update
* ``DELETE /api/webhooks/{id}``            — delete
* ``POST   /api/webhooks/{id}/test``       — send synthetic event now
* ``GET    /api/webhooks/{id}/deliveries`` — recent attempts log

OpSec
-----
* All URLs are validated through ``app.core.ssrf.assert_url_allowed`` on
  create / update / test. SSRF blocks short-circuit before any payload
  is built.
* The ``secret`` field is generated server-side when absent. It is
  returned **once** in the create response, then masked on every
  subsequent read.
* Payload uses only CVE-level signals — no asset egress.
"""
from __future__ import annotations

from typing import Any

import asyncpg
import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.core.config import Settings, get_settings
from app.core.http import OpsecAwareClient
from app.core.ssrf import SsrfBlockedError, assert_url_allowed
from app.services.webhooks import (
    ALLOWED_EVENT_TYPES,
    build_finding_event,
    generate_secret,
    public_view,
    serialize_payload,
    sign,
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

_HOST_ALLOWLIST_ENV_KEY = "WEBHOOK_HOST_ALLOWLIST"


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


def _get_allowlist(settings: Settings) -> str:
    # Settings model does not yet declare WEBHOOK_HOST_ALLOWLIST — read
    # via env override on the underlying object so we do not break
    # existing config schemas.
    import os

    return os.environ.get(_HOST_ALLOWLIST_ENV_KEY, "")


# ─────────────────────────────────────────────────────── request models

class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=2000)
    secret: str | None = Field(default=None, max_length=200)
    event_types: list[str]
    min_priority: int | None = Field(default=None, ge=0, le=100)
    enabled: bool = True
    created_by: str | None = None

    @field_validator("event_types")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("event_types must not be empty")
        bad = [e for e in v if e not in ALLOWED_EVENT_TYPES]
        if bad:
            raise ValueError(
                f"unknown event_types: {bad} (allowed: {sorted(ALLOWED_EVENT_TYPES)})"
            )
        return v


class WebhookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    url: str | None = Field(default=None, min_length=1, max_length=2000)
    secret: str | None = Field(default=None, max_length=200)
    event_types: list[str] | None = None
    min_priority: int | None = Field(default=None, ge=0, le=100)
    enabled: bool | None = None

    @field_validator("event_types")
    @classmethod
    def _validate_events(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        bad = [e for e in v if e not in ALLOWED_EVENT_TYPES]
        if bad:
            raise ValueError(
                f"unknown event_types: {bad} (allowed: {sorted(ALLOWED_EVENT_TYPES)})"
            )
        return v


# ─────────────────────────────────────────────────────────── routes

@router.post("")
async def create_webhook(
    body: WebhookCreate,
    pool: asyncpg.Pool = Depends(_get_pool),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    try:
        assert_url_allowed(body.url, allowlist=_get_allowlist(settings))
    except SsrfBlockedError as exc:
        raise HTTPException(status_code=400, detail=f"url_rejected:{exc}") from exc

    secret = body.secret or generate_secret()

    row = await pool.fetchrow(
        """
        INSERT INTO webhooks (name, url, secret, event_types, min_priority, enabled, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        """,
        body.name,
        body.url,
        secret,
        body.event_types,
        body.min_priority,
        body.enabled,
        body.created_by,
    )

    # Return the full secret on the *create* response only — clients must
    # store it themselves; subsequent reads return a mask.
    if row is None:
        raise HTTPException(500, "insert failed")
    out = dict(row)
    return out


@router.get("")
async def list_webhooks(
    pool: asyncpg.Pool = Depends(_get_pool),
    enabled: bool | None = None,
) -> dict[str, Any]:
    if enabled is None:
        rows = await pool.fetch("SELECT * FROM webhooks ORDER BY id DESC")
    else:
        rows = await pool.fetch(
            "SELECT * FROM webhooks WHERE enabled = $1 ORDER BY id DESC", enabled
        )
    return {"data": [public_view(r) for r in rows], "total": len(rows)}


@router.get("/{webhook_id}")
async def get_webhook(
    webhook_id: int, pool: asyncpg.Pool = Depends(_get_pool)
) -> dict[str, Any]:
    row = await pool.fetchrow("SELECT * FROM webhooks WHERE id = $1", webhook_id)
    if row is None:
        raise HTTPException(404, "webhook not found")
    return public_view(row)


@router.patch("/{webhook_id}")
async def update_webhook(
    webhook_id: int,
    body: WebhookUpdate,
    pool: asyncpg.Pool = Depends(_get_pool),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if body.url is not None:
        try:
            assert_url_allowed(body.url, allowlist=_get_allowlist(settings))
        except SsrfBlockedError as exc:
            raise HTTPException(status_code=400, detail=f"url_rejected:{exc}") from exc

    row = await pool.fetchrow(
        """
        UPDATE webhooks
        SET name         = COALESCE($2, name),
            url          = COALESCE($3, url),
            secret       = COALESCE($4, secret),
            event_types  = COALESCE($5, event_types),
            min_priority = COALESCE($6, min_priority),
            enabled      = COALESCE($7, enabled),
            updated_at   = NOW()
        WHERE id = $1
        RETURNING *
        """,
        webhook_id,
        body.name,
        body.url,
        body.secret,
        body.event_types,
        body.min_priority,
        body.enabled,
    )
    if row is None:
        raise HTTPException(404, "webhook not found")
    return public_view(row)


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: int, pool: asyncpg.Pool = Depends(_get_pool)
) -> dict[str, str]:
    result = await pool.execute("DELETE FROM webhooks WHERE id = $1", webhook_id)
    if result.endswith(" 0"):
        raise HTTPException(404, "webhook not found")
    return {"status": "deleted"}


@router.post("/{webhook_id}/test")
async def test_webhook(
    webhook_id: int,
    pool: asyncpg.Pool = Depends(_get_pool),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Send a synthetic ``finding.created_high_priority`` event right now.

    Used by the UI's "Test webhook" button. The request is not enqueued
    via the worker (no DB row) — it is a one-shot call that returns the
    upstream status code.
    """
    row = await pool.fetchrow(
        "SELECT id, url, secret FROM webhooks WHERE id = $1", webhook_id
    )
    if row is None:
        raise HTTPException(404, "webhook not found")

    try:
        assert_url_allowed(row["url"], allowlist=_get_allowlist(settings))
    except SsrfBlockedError as exc:
        raise HTTPException(400, f"url_rejected:{exc}") from exc

    payload = build_finding_event(
        event_type="finding.created_high_priority",
        cve_id="CVE-2024-TEST",
        severity="HIGH",
        priority_score=80,
        affected_count=1,
        is_kev=False,
        has_public_poc=None,
        has_nuclei_template=None,
    )
    body = serialize_payload(payload)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "cve-management-webhook/1.0",
    }
    if row["secret"]:
        headers["X-Signature"] = sign(body, row["secret"])

    async with OpsecAwareClient(
        provider="webhook",
        enforcement=settings.opsec_enforcement,
        timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
    ) as client:
        try:
            resp = await client.post(row["url"], content=body, headers=headers)
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}
        return {
            "ok": 200 <= resp.status_code < 300,
            "status_code": resp.status_code,
            "response_excerpt": resp.text[:500],
        }


@router.get("/{webhook_id}/deliveries")
async def list_deliveries(
    webhook_id: int,
    pool: asyncpg.Pool = Depends(_get_pool),
    limit: int = 50,
) -> dict[str, Any]:
    limit = max(1, min(200, limit))
    rows = await pool.fetch(
        """
        SELECT id, event_type, status_code, attempts, scheduled_at,
               delivered_at, last_error, created_at
        FROM webhook_deliveries
        WHERE webhook_id = $1
        ORDER BY id DESC
        LIMIT $2
        """,
        webhook_id,
        limit,
    )
    return {"data": [dict(r) for r in rows], "total": len(rows)}
