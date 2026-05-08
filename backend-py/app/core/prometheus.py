"""Prometheus metrics exposition (Sprint 3 — S3.7).

We keep the in-process ``MetricsRegistry`` (``app/core/metrics.py``)
as the human-readable JSON snapshot at ``/api/health/metrics`` — it's
the same shape the dashboard already consumes — and **mirror** the
counters into Prometheus collectors here. The duplication is
intentional: callers that pre-date this module keep working
unchanged, and Prometheus scrapers get the standard textfile format
without translating JSON.

A single ``CollectorRegistry`` is created module-level so the same
counters are reused across requests (Prometheus rejects duplicate
registrations on the global default registry, and that surfaces as
500s under uvicorn --reload).

Naming follows Prometheus conventions:
  * ``http_requests_total{method,path,status}`` — labels intentionally
    cardinality-bounded (the path is the *route template*, not the URL).
  * ``http_request_duration_seconds`` — histogram with buckets tuned
    for an interactive dashboard (50ms .. 2s).
  * ``provider_*`` — per-upstream metrics, mirrored from
    ``ProviderMetrics``.
  * ``circuit_breaker_state`` — gauge with one series per breaker;
    value 0 closed / 1 half-open / 2 open. Surfaces in alerts.
  * ``opsec_egress_blocked_total{provider,reason}`` — counter that
    must be alarmed if it ever moves in production (it shouldn't).

Endpoint: ``GET /metrics`` (added to the FastAPI app in
``app/api/routers/health.py``).
"""
from __future__ import annotations

from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Dedicated registry — never the default. Avoids cross-test bleed and
# duplicate-registration storms when uvicorn reloads.
REGISTRY = CollectorRegistry()


HTTP_REQUESTS = Counter(
    "http_requests_total",
    "Total HTTP requests handled by the backend.",
    labelnames=("method", "path", "status"),
    registry=REGISTRY,
)

HTTP_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds.",
    labelnames=("method", "path"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=REGISTRY,
)

PROVIDER_REQUESTS = Counter(
    "provider_requests_total",
    "Outbound requests to upstream CVE providers.",
    labelnames=("provider",),
    registry=REGISTRY,
)
PROVIDER_ERRORS = Counter(
    "provider_errors_total",
    "Outbound provider call failures (any non-2xx after retries).",
    labelnames=("provider",),
    registry=REGISTRY,
)
PROVIDER_RATE_LIMITED = Counter(
    "provider_rate_limited_total",
    "Outbound provider calls that hit our token-bucket rate limiter.",
    labelnames=("provider",),
    registry=REGISTRY,
)
PROVIDER_CIRCUIT_OPENS = Counter(
    "provider_circuit_opens_total",
    "Times the per-provider circuit breaker opened.",
    labelnames=("provider",),
    registry=REGISTRY,
)
PROVIDER_LATENCY = Histogram(
    "provider_request_duration_seconds",
    "Outbound provider request duration in seconds.",
    labelnames=("provider",),
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    registry=REGISTRY,
)

CIRCUIT_STATE = Gauge(
    "circuit_breaker_state",
    "Per-provider circuit breaker state. 0=closed, 1=half_open, 2=open.",
    labelnames=("provider",),
    registry=REGISTRY,
)

EGRESS_BLOCKED = Counter(
    "opsec_egress_blocked_total",
    "OpSec violations: outbound bodies blocked before leaving the perimeter.",
    labelnames=("provider", "reason"),
    registry=REGISTRY,
)


_STATE_VALUES = {"closed": 0, "half_open": 1, "open": 2}


def record_http(method: str, path: str, status: int, duration_s: float) -> None:
    """Called by an ASGI middleware on every response. ``path`` MUST be
    the route template (FastAPI route.path), not the raw URL — otherwise
    cardinality explodes."""
    HTTP_REQUESTS.labels(method=method, path=path, status=str(status)).inc()
    HTTP_DURATION.labels(method=method, path=path).observe(duration_s)


def record_provider_request(provider: str, duration_s: float) -> None:
    PROVIDER_REQUESTS.labels(provider=provider).inc()
    PROVIDER_LATENCY.labels(provider=provider).observe(duration_s)


def record_provider_error(provider: str) -> None:
    PROVIDER_ERRORS.labels(provider=provider).inc()


def record_provider_rate_limited(provider: str) -> None:
    PROVIDER_RATE_LIMITED.labels(provider=provider).inc()


def record_provider_circuit_open(provider: str) -> None:
    PROVIDER_CIRCUIT_OPENS.labels(provider=provider).inc()


def record_egress_block(provider: str, reason: str) -> None:
    EGRESS_BLOCKED.labels(provider=provider, reason=reason).inc()


def update_circuit_state(provider: str, state: str) -> None:
    CIRCUIT_STATE.labels(provider=provider).set(_STATE_VALUES.get(state, 0))


def render() -> tuple[bytes, str]:
    """Return ``(body, content_type)`` for the /metrics endpoint."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def sync_breakers(breakers: dict[str, Any]) -> None:
    """Refresh CIRCUIT_STATE gauges from the live breaker dict.
    Called from the metrics endpoint so the gauge stays in sync with the
    breaker FSM without instrumenting every transition."""
    for name, cb in breakers.items():
        try:
            update_circuit_state(name, cb.state.value)
        except Exception:  # pragma: no cover — defensive
            continue
