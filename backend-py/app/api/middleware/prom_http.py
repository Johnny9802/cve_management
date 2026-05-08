"""ASGI middleware that feeds the Prometheus HTTP counters (S3.7).

Plain ASGI wrapper (not Starlette BaseHTTPMiddleware) so streaming
responses keep streaming. Captures method + the matched route
template (NOT the raw URL — bounding cardinality is the whole point
of using Prometheus instead of structured logs for this).
"""
from __future__ import annotations

import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.prometheus import record_http


class PrometheusHttpMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.monotonic()
        status_code = {"v": 500}  # default to 500 if response.start never arrives

        async def capture(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_code["v"] = int(message.get("status", 500))
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            duration = time.monotonic() - start
            method = scope.get("method", "UNKNOWN")
            # Prefer the route template over the raw path; falls back to
            # the literal path on misses (e.g. 404s).
            route = scope.get("route")
            path = getattr(route, "path", None) or scope.get("path", "")
            record_http(method, path, status_code["v"], duration)
