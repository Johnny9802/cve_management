"""Webhook utilities — payload building, HMAC signing, dedup.

Used by both the API router (test endpoint) and the delivery worker.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger(__name__)


# Events the platform emits in v1.
ALLOWED_EVENT_TYPES: frozenset[str] = frozenset({
    "finding.created_high_priority",
    "finding.kev_match",
    "finding.exploitability_changed",
    "cve.published_critical",
})


def generate_secret() -> str:
    """Return a 32-byte URL-safe secret."""
    return secrets.token_urlsafe(32)


def mask_secret(secret: str | None) -> str | None:
    """Mask a webhook secret for API responses / logs."""
    if not secret:
        return None
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "…" + secret[-4:]


def serialize_payload(payload: dict[str, Any]) -> bytes:
    """Stable, deterministic JSON encoding for HMAC consistency."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(payload: bytes, secret: str) -> str:
    """Compute the ``X-Signature`` value for a payload."""
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def build_finding_event(
    *,
    event_type: str,
    cve_id: str,
    severity: str | None,
    priority_score: float | int | None,
    affected_count: int,
    is_kev: bool,
    has_public_poc: bool | None,
    has_nuclei_template: bool | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a webhook payload for a finding-related event.

    The payload deliberately excludes asset metadata: no hostname / IP /
    asset_id / inventory list. Only CVE-level signals plus a count of
    affected products. This is the OpSec contract for outbound webhooks.
    """
    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError(f"unknown event_type: {event_type}")
    body: dict[str, Any] = {
        "event_type": event_type,
        "cve_id": cve_id,
        "severity": severity,
        "priority_score": priority_score,
        "affected_count": affected_count,
        "is_kev": is_kev,
        "has_public_poc": has_public_poc,
        "has_nuclei_template": has_nuclei_template,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }
    if extra:
        # Allow extension only with whitelisted keys.
        for key in ("delta_score", "previous_priority_score"):
            if key in extra:
                body[key] = extra[key]
    return body


# ------------------------------------------------------------------ dedup

_DEDUP_WINDOW_SECONDS = 5 * 60  # 5 min


async def is_duplicate(
    pool: asyncpg.Pool,
    *,
    webhook_id: int,
    event_type: str,
    dedup_key: str,
) -> bool:
    """Return True if a delivery row for the same (webhook, event, key)
    has been *enqueued* in the last 5 minutes (regardless of outcome)."""
    row = await pool.fetchrow(
        """
        SELECT 1 FROM webhook_deliveries
        WHERE webhook_id = $1
          AND event_type = $2
          AND dedup_key  = $3
          AND created_at > NOW() - INTERVAL '%(s)s seconds'
        LIMIT 1
        """ % {"s": _DEDUP_WINDOW_SECONDS},
        webhook_id,
        event_type,
        dedup_key,
    )
    return row is not None


async def find_subscribers(
    pool: asyncpg.Pool,
    *,
    event_type: str,
    priority_score: float | int | None,
) -> list[asyncpg.Record]:
    """Return enabled webhooks that are subscribed to ``event_type`` and
    whose ``min_priority`` filter passes.
    """
    return list(
        await pool.fetch(
            """
            SELECT id, name, url, secret, event_types, min_priority
            FROM webhooks
            WHERE enabled = TRUE
              AND $1 = ANY(event_types)
              AND ($2::int IS NULL OR min_priority IS NULL OR min_priority <= $2)
            """,
            event_type,
            int(priority_score) if priority_score is not None else None,
        )
    )


async def enqueue_delivery(
    pool: asyncpg.Pool,
    *,
    webhook_id: int,
    event_type: str,
    payload: dict[str, Any],
    dedup_key: str | None,
) -> int | None:
    """Insert a row into ``webhook_deliveries``. Returns the new id or
    ``None`` if the dedup window suppressed the insert."""
    if dedup_key and await is_duplicate(
        pool, webhook_id=webhook_id, event_type=event_type, dedup_key=dedup_key
    ):
        return None
    row = await pool.fetchrow(
        """
        INSERT INTO webhook_deliveries
            (webhook_id, event_type, payload, dedup_key)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        """,
        webhook_id,
        event_type,
        json.dumps(payload),
        dedup_key,
    )
    return int(row["id"]) if row else None


def public_view(row: asyncpg.Record | dict[str, Any]) -> dict[str, Any]:
    """Convert a webhook row into a JSON-friendly dict with masked secret."""
    d = dict(row)
    if "secret" in d:
        d["secret"] = mask_secret(d["secret"])
    return d
