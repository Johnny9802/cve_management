"""Security headers middleware (Sprint 1 — S1.6).

Adds defense-in-depth response headers on every API response:

* ``Content-Security-Policy`` — restrictive but compatible with FastAPI's
  Swagger UI (which loads from cdn.jsdelivr.net). API JSON responses are
  unaffected by CSP; the policy is meaningful for the docs HTML pages.
* ``Strict-Transport-Security`` — only emitted in ``production`` so it
  doesn't pin localhost to HTTPS during development.
* ``X-Frame-Options: DENY`` — backend never serves embeddable HTML.
* ``X-Content-Type-Options: nosniff``
* ``Referrer-Policy: strict-origin-when-cross-origin``
* ``Permissions-Policy`` — disables sensors the API has no business
  requesting.

The middleware is intentionally a plain ASGI wrapper (no Starlette
``BaseHTTPMiddleware``) to avoid the streaming-response buffering bug in
Starlette < 0.40.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# CSP that allows Swagger UI (loaded from jsdelivr) while still blocking
# arbitrary script execution. JSON API responses ignore CSP entirely.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

_PERMISSIONS_POLICY = (
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
    "magnetometer=(), microphone=(), payment=(), usb=()"
)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, environment: str = "development") -> None:
        self.app = app
        self.environment = environment

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                _set(headers, b"content-security-policy", _CSP.encode())
                _set(headers, b"x-frame-options", b"DENY")
                _set(headers, b"x-content-type-options", b"nosniff")
                _set(headers, b"referrer-policy", b"strict-origin-when-cross-origin")
                _set(headers, b"permissions-policy", _PERMISSIONS_POLICY.encode())
                if self.environment == "production":
                    _set(
                        headers,
                        b"strict-transport-security",
                        b"max-age=31536000; includeSubDomains",
                    )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _set(headers: list[tuple[bytes, bytes]], key: bytes, value: bytes) -> None:
    """Replace or append a header by lowercase key (ASGI uses bytes)."""
    lower = key.lower()
    for i, (k, _) in enumerate(headers):
        if k.lower() == lower:
            headers[i] = (key, value)
            return
    headers.append((key, value))


def add_security_headers(app: Callable[..., Awaitable[None]], *, environment: str) -> None:
    """Public helper kept for API symmetry with ``add_error_handler``."""
    # FastAPI / Starlette exposes ``add_middleware`` on the app object.
    app.add_middleware(SecurityHeadersMiddleware, environment=environment)  # type: ignore[attr-defined]
