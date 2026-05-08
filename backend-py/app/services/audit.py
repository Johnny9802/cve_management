"""Audit log writer (P9 partial — Sprint 3).

The Sprint 3 brief explicitly excludes RBAC. This module therefore exposes
a minimal interface:

* ``record(...)`` — insert a row into ``audit_log``.
* ``mask_sensitive(...)`` — strip secrets / tokens from a diff payload
  before persisting it.

Atomicity
---------
``record_in_tx(conn, ...)`` accepts an existing transactional connection
so callers can write the audit row inside the same transaction as the
state change they describe. If the parent transaction rolls back, the
audit row rolls back too — preventing fake audit entries when the actual
operation fails. This honours the brief's "se transazione principale
fallisce, non creare audit falso" requirement.

Default actor
-------------
* ``actor_email`` defaults to ``"system"`` for scheduler-driven jobs and
  ``"anonymous"`` for API calls without an X-Actor-Email hint.
* ``actor_role`` defaults to ``"unknown"``.

These defaults preserve the table NOT NULL invariants on the legacy
``actor`` column (migration 0002) while allowing the new
``actor_email`` / ``actor_role`` columns to remain nullable / explicit.
"""
from __future__ import annotations

import json
import re
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger(__name__)

DEFAULT_SYSTEM_ACTOR = "system"
DEFAULT_ANONYMOUS_ACTOR = "anonymous"
DEFAULT_ROLE = "unknown"

# Keys whose values must NEVER appear in the audit diff. Matched
# case-insensitively at the leaf level. Webhook secrets and API keys are
# the obvious targets.
_SENSITIVE_KEY_PATTERNS = (
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"authorization", re.IGNORECASE),
)
# Webhook URL is also masked: the path/query may carry a token.
_URL_KEY = re.compile(r"^url$", re.IGNORECASE)


def _is_sensitive(key: str) -> bool:
    return any(p.search(key) for p in _SENSITIVE_KEY_PATTERNS)


def mask_sensitive(value: Any) -> Any:
    """Walk a JSON-shaped value and mask sensitive leaves.

    Lists and dicts are walked recursively. Scalars are returned
    unchanged. The function is idempotent.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if _is_sensitive(k):
                out[k] = "***" if v else None
            elif _URL_KEY.match(k) and isinstance(v, str):
                out[k] = _mask_url(v)
            else:
                out[k] = mask_sensitive(v)
        return out
    if isinstance(value, list):
        return [mask_sensitive(v) for v in value]
    return value


def _mask_url(url: str) -> str:
    """Drop query string + path; keep scheme + host so the audit reader
    can still tell where the webhook was pointed at."""
    if not isinstance(url, str):
        return url
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or ""
        scheme = parsed.scheme or "https"
        return f"{scheme}://{host}/***" if host else "***"
    except Exception:  # pragma: no cover
        return "***"


# ────────────────────────────────────────────────────── records


_INSERT_SQL = """
    INSERT INTO audit_log (
        action, actor, actor_email, actor_role,
        target_type, target_id,
        diff, metadata, ip_address, user_agent, ts
    )
    VALUES (
        $1, $2, $3, $4,
        $5, $6,
        $7::jsonb, $8::jsonb, $9::inet, $10, NOW()
    )
    RETURNING id
"""


async def record(
    pool: asyncpg.Pool,
    *,
    action: str,
    target_type: str | None,
    target_id: str | None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    diff: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> int | None:
    """Best-effort audit record outside a transaction. Logs and swallows
    on failure; never raises.
    """
    try:
        async with pool.acquire() as conn:
            row_id = await record_in_tx(
                conn,
                action=action,
                target_type=target_type,
                target_id=target_id,
                actor_email=actor_email,
                actor_role=actor_role,
                diff=diff,
                metadata=metadata,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            return row_id
    except Exception as exc:
        logger.warning("audit.record_failed", error=str(exc), action=action)
        return None


async def record_in_tx(
    conn: asyncpg.Connection,
    *,
    action: str,
    target_type: str | None,
    target_id: str | None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    diff: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> int:
    """Insert audit row inside an existing transaction. Caller is
    responsible for the surrounding ``async with conn.transaction()``.
    """
    masked_diff = mask_sensitive(diff) if diff else None
    masked_meta = mask_sensitive(metadata) if metadata else None
    actor = actor_email or DEFAULT_ANONYMOUS_ACTOR
    role = actor_role or DEFAULT_ROLE
    row = await conn.fetchrow(
        _INSERT_SQL,
        action,
        actor,                      # legacy `actor` column from 0002
        actor,                      # new `actor_email`
        role,
        target_type,
        target_id,
        json.dumps(masked_diff) if masked_diff is not None else None,
        json.dumps(masked_meta) if masked_meta is not None else "{}",
        ip_address,
        user_agent,
    )
    return int(row["id"]) if row else 0
