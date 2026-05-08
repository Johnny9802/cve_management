"""Webhook delivery worker (P7).

A long-running background task driven by APScheduler. On each tick it
claims a small batch of due deliveries from the ``webhook_deliveries``
table using ``FOR UPDATE SKIP LOCKED``, attempts an HTTP POST to each,
records the outcome, and reschedules failures using exponential
back-off with jitter.

Retry schedule (attempts → next delay):
  1 → 1 min
  2 → 5 min
  3 → 30 min
  4 → 2 h
  5 → 12 h (final attempt; after this the row stays as undelivered with
            ``attempts >= max_attempts`` and stops being picked up).

Security
--------
* OpSec wrapper enforces "no asset egress" on every payload.
* SSRF guard runs once per delivery (DNS may have changed) before the
  POST. A failed guard moves the delivery to the failure path.
* HMAC SHA-256 signature in ``X-Signature`` when ``webhooks.secret`` is
  set.
"""
from __future__ import annotations

import asyncio
import json
import random
from datetime import UTC, datetime, timedelta

import asyncpg
import httpx
import structlog

from app.core.config import Settings
from app.core.http import OpsecAwareClient, OpsecViolationError
from app.core.ssrf import SsrfBlockedError, assert_url_allowed
from app.services.webhooks import serialize_payload, sign

logger = structlog.get_logger(__name__)

_BATCH_SIZE = 20
_LOCK_DURATION_SECONDS = 60

# attempt index → seconds to next try (after the *next* attempt)
_BACKOFF_SECONDS: tuple[int, ...] = (
    60,           # after attempt 1 fails → wait 1 min
    5 * 60,       # 5 min
    30 * 60,      # 30 min
    2 * 3600,     # 2 h
    12 * 3600,    # 12 h
)


_CLAIM_SQL = f"""
    WITH due AS (
        SELECT id
        FROM webhook_deliveries
        WHERE delivered_at IS NULL
          AND attempts < max_attempts
          AND scheduled_at <= NOW()
          AND (locked_until IS NULL OR locked_until <= NOW())
        ORDER BY scheduled_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT $1
    )
    UPDATE webhook_deliveries d
    SET locked_until = NOW() + INTERVAL '{_LOCK_DURATION_SECONDS} seconds',
        attempts     = attempts + 1
    FROM due
    WHERE d.id = due.id
    RETURNING d.id, d.webhook_id, d.event_type, d.payload, d.attempts, d.max_attempts
"""


_MARK_SUCCESS_SQL = """
    UPDATE webhook_deliveries
    SET delivered_at = NOW(),
        status_code  = $2,
        response_body = $3,
        last_error   = NULL,
        locked_until = NULL
    WHERE id = $1
"""

_MARK_FAILURE_SQL = """
    UPDATE webhook_deliveries
    SET status_code  = $2,
        response_body = $3,
        last_error   = $4,
        locked_until = NULL,
        scheduled_at = $5
    WHERE id = $1
"""

_BUMP_WEBHOOK_SUCCESS_SQL = """
    UPDATE webhooks
    SET last_success_at = NOW()
    WHERE id = $1
"""

_BUMP_WEBHOOK_FAILURE_SQL = """
    UPDATE webhooks
    SET last_error_at = NOW(),
        last_error    = $2
    WHERE id = $1
"""


def _next_attempt_delay(next_attempt_idx: int) -> float:
    """Return seconds to wait before attempt index ``next_attempt_idx``.

    ``next_attempt_idx`` is 1-based. Adds 0–25% jitter.
    """
    bucket = min(max(0, next_attempt_idx - 1), len(_BACKOFF_SECONDS) - 1)
    base = _BACKOFF_SECONDS[bucket]
    jitter = random.uniform(0.0, 0.25 * base)
    return base + jitter


async def _fetch_webhook_target(
    pool: asyncpg.Pool, webhook_id: int
) -> asyncpg.Record | None:
    return await pool.fetchrow(
        "SELECT id, url, secret, enabled FROM webhooks WHERE id = $1", webhook_id
    )


async def _attempt_delivery(
    pool: asyncpg.Pool,
    settings: Settings,
    delivery: asyncpg.Record,
    *,
    allowlist: str = "",
) -> bool:
    """Attempt one delivery. Returns True on success."""
    delivery_id = delivery["id"]
    webhook_id = delivery["webhook_id"]

    target = await _fetch_webhook_target(pool, webhook_id)
    if target is None:
        # Webhook deleted between enqueue and dispatch.
        await pool.execute(_MARK_SUCCESS_SQL, delivery_id, 410, "webhook_deleted")
        return True
    if not target["enabled"]:
        await _record_failure(
            pool,
            delivery,
            status_code=None,
            error="webhook_disabled",
        )
        return False

    try:
        assert_url_allowed(target["url"], allowlist=allowlist)
    except SsrfBlockedError as exc:
        await _record_failure(
            pool,
            delivery,
            status_code=None,
            error=f"ssrf_blocked:{exc}",
        )
        await pool.execute(_BUMP_WEBHOOK_FAILURE_SQL, webhook_id, f"ssrf_blocked:{exc}")
        return False

    payload = delivery["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    body = serialize_payload(payload)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "cve-management-webhook/1.0",
        "X-Webhook-Delivery-Id": str(delivery_id),
    }
    if target["secret"]:
        headers["X-Signature"] = sign(body, target["secret"])

    async with OpsecAwareClient(
        provider="webhook",
        enforcement=settings.opsec_enforcement,
        timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
    ) as client:
        try:
            resp = await client.post(target["url"], content=body, headers=headers)
        except OpsecViolationError as exc:
            await _record_failure(
                pool, delivery, status_code=None, error=f"opsec_violation:{exc.reason}"
            )
            return False
        except httpx.HTTPError as exc:
            await _record_failure(
                pool, delivery, status_code=None, error=f"http_error:{exc}"
            )
            return False

    if 200 <= resp.status_code < 300:
        await pool.execute(
            _MARK_SUCCESS_SQL, delivery_id, resp.status_code, resp.text[:2000]
        )
        await pool.execute(_BUMP_WEBHOOK_SUCCESS_SQL, webhook_id)
        return True

    await _record_failure(
        pool,
        delivery,
        status_code=resp.status_code,
        error=f"http_{resp.status_code}",
        response_body=resp.text[:2000],
    )
    await pool.execute(
        _BUMP_WEBHOOK_FAILURE_SQL, webhook_id, f"http_{resp.status_code}"
    )
    return False


async def _record_failure(
    pool: asyncpg.Pool,
    delivery: asyncpg.Record,
    *,
    status_code: int | None,
    error: str,
    response_body: str | None = None,
) -> None:
    next_attempt = int(delivery["attempts"]) + 1  # this attempt failed
    max_attempts = int(delivery["max_attempts"])
    if next_attempt >= max_attempts:
        # Final attempt failed: record but do not reschedule.
        await pool.execute(
            _MARK_FAILURE_SQL,
            delivery["id"],
            status_code,
            response_body,
            error,
            datetime.now(tz=UTC),
        )
        logger.warning(
            "webhook.delivery.giving_up",
            delivery_id=delivery["id"],
            webhook_id=delivery["webhook_id"],
            attempts=delivery["attempts"],
            error=error,
        )
        return

    delay = _next_attempt_delay(next_attempt + 1)
    new_schedule = datetime.now(tz=UTC) + timedelta(seconds=delay)
    await pool.execute(
        _MARK_FAILURE_SQL,
        delivery["id"],
        status_code,
        response_body,
        error,
        new_schedule,
    )
    logger.info(
        "webhook.delivery.retry_scheduled",
        delivery_id=delivery["id"],
        webhook_id=delivery["webhook_id"],
        attempts=delivery["attempts"],
        next_attempt_in_s=int(delay),
        error=error,
    )


async def drain_pending_deliveries(
    pool: asyncpg.Pool, settings: Settings, *, allowlist: str = ""
) -> int:
    """Process up to ``_BATCH_SIZE`` due deliveries. Returns the count
    of attempts made (success or failure)."""
    async with pool.acquire() as conn, conn.transaction():
        claimed = await conn.fetch(_CLAIM_SQL, _BATCH_SIZE)
    if not claimed:
        return 0

    sem = asyncio.Semaphore(8)

    async def _bounded(d: asyncpg.Record) -> None:
        async with sem:
            try:
                await _attempt_delivery(pool, settings, d, allowlist=allowlist)
            except Exception as exc:
                logger.error(
                    "webhook.delivery.unexpected_error",
                    delivery_id=d["id"],
                    error=str(exc),
                    exc_info=True,
                )
                await _record_failure(
                    pool, d, status_code=None, error=f"internal:{exc}"
                )

    await asyncio.gather(*(_bounded(d) for d in claimed))
    return len(claimed)


__all__ = ["drain_pending_deliveries"]
