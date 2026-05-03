"""HTTP middleware: request context, structured logging, HTTP metrics."""
from __future__ import annotations

import time
import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = structlog.get_logger(__name__)


def add_error_handler(app: FastAPI) -> None:

    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = str(uuid.uuid4())
        t0 = time.monotonic()

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )

        response = await call_next(request)

        duration_ms = int((time.monotonic() - t0) * 1000)
        status = response.status_code

        # Skip health + metrics spam from logs in debug mode
        if request.url.path not in ("/api/health", "/api/health/metrics"):
            logger.info(
                "http.request",
                status=status,
                duration_ms=duration_ms,
            )

        # Record HTTP metrics if registry is available
        try:
            metrics = request.app.state.metrics
            metrics.http.record(latency_s=(duration_ms / 1000), status=status)
        except AttributeError:
            pass  # metrics not yet initialized (startup phase)

        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_error", exc_type=type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"},
            headers={
                "X-Request-ID": structlog.contextvars.get_contextvars().get("request_id", "")
            },
        )
