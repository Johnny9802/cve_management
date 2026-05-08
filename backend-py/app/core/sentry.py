"""Sentry initialization (Sprint 3 — S3.6).

Self-contained init wrapper:
  * No-op when ``settings.sentry_dsn`` is empty (the default and the
    expected dev/CI posture). The lifespan logs once at startup so an
    operator can tell from the boot log whether errors are being
    captured.
  * Always strips PII: ``send_default_pii=False`` and a custom
    ``before_send`` that scrubs Authorization headers, cookies, and
    request bodies before they leave the process. Sentry already
    scrubs query strings, but we belt-and-brace.
  * Performance tracing is opt-in via ``SENTRY_TRACES_SAMPLE_RATE``
    (defaults to 0). Keep it off in single-instance deployments —
    the in-process metrics already cover request latency.
"""
from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


_SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key"}


def _scrub_event(event: dict[str, Any], _hint: dict[str, Any]) -> dict[str, Any]:
    """``before_send`` hook. Drops any leftover headers that contain
    secrets and removes the request body entirely — Sentry has no
    business carrying user-submitted JSON to a third party."""
    request = event.get("request") or {}
    headers = request.get("headers")
    if isinstance(headers, dict):
        for key in list(headers):
            if key.lower() in _SENSITIVE_HEADERS:
                headers[key] = "[scrubbed]"
    elif isinstance(headers, list):
        request["headers"] = [
            (k, "[scrubbed]" if k.lower() in _SENSITIVE_HEADERS else v)
            for (k, v) in headers
        ]
    request.pop("data", None)
    request.pop("cookies", None)
    event["request"] = request
    # User context — never include real email; strip down to id + role.
    user = event.get("user") or {}
    event["user"] = {k: v for k, v in user.items() if k in {"id", "role"}}
    return event


def init_sentry(*, dsn: str, environment: str, traces_sample_rate: float = 0.0) -> bool:
    """Initialize the Sentry SDK. Returns True if active, False if no-op.

    Imported lazily so test runs that never hit prod can stay offline.
    """
    if not dsn:
        logger.info("sentry.disabled", reason="empty DSN — set SENTRY_DSN to enable")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.asyncio import AsyncioIntegration
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration
    except ImportError as exc:  # pragma: no cover — install hint
        logger.warning("sentry.import_failed", error=str(exc))
        return False

    sentry_sdk.init(
        dsn=dsn,
        environment=environment,
        send_default_pii=False,
        traces_sample_rate=max(0.0, min(1.0, traces_sample_rate)),
        before_send=_scrub_event,
        integrations=[
            FastApiIntegration(transaction_style="endpoint"),
            StarletteIntegration(transaction_style="endpoint"),
            AsyncioIntegration(),
        ],
    )
    logger.info(
        "sentry.enabled",
        environment=environment,
        traces_sample_rate=traces_sample_rate,
    )
    return True
