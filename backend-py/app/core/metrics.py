"""In-process metrics registry — no external Prometheus client dependency.

Stores per-provider counters and a sliding window of latency samples (last 1000).
Exposed as JSON via GET /api/health/metrics.

Thread/task safety: single-threaded asyncio — no explicit lock needed.
Upgrade path: replace this module with prometheus_client if Prometheus scraping is required.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderMetrics:
    provider: str
    requests_total: int = 0
    rate_limited_total: int = 0
    errors_total: int = 0
    circuit_opens_total: int = 0
    _latencies_s: deque[float] = field(default_factory=lambda: deque(maxlen=1000))

    def record_request(self, latency_s: float) -> None:
        self.requests_total += 1
        self._latencies_s.append(latency_s)

    def record_rate_limited(self) -> None:
        self.rate_limited_total += 1

    def record_error(self) -> None:
        self.errors_total += 1

    def record_circuit_open(self) -> None:
        self.circuit_opens_total += 1

    def _percentile(self, p: float) -> float | None:
        if len(self._latencies_s) < 5:
            return None
        s = sorted(self._latencies_s)
        idx = max(0, int(len(s) * p) - 1)
        return round(s[idx] * 1000, 1)

    def snapshot(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "requests_total": self.requests_total,
            "rate_limited_total": self.rate_limited_total,
            "errors_total": self.errors_total,
            "circuit_opens_total": self.circuit_opens_total,
            "latency_p50_ms": self._percentile(0.50),
            "latency_p95_ms": self._percentile(0.95),
            "latency_p99_ms": self._percentile(0.99),
            "sample_count": len(self._latencies_s),
        }


@dataclass
class HttpMetrics:
    """Aggregate HTTP request metrics for the FastAPI app itself."""
    requests_total: int = 0
    errors_5xx_total: int = 0
    _latencies_s: deque[float] = field(default_factory=lambda: deque(maxlen=2000))

    def record(self, latency_s: float, status: int) -> None:
        self.requests_total += 1
        self._latencies_s.append(latency_s)
        if status >= 500:
            self.errors_5xx_total += 1

    def _percentile(self, p: float) -> float | None:
        if len(self._latencies_s) < 5:
            return None
        s = sorted(self._latencies_s)
        idx = max(0, int(len(s) * p) - 1)
        return round(s[idx] * 1000, 1)

    def snapshot(self) -> dict[str, Any]:
        return {
            "requests_total": self.requests_total,
            "errors_5xx_total": self.errors_5xx_total,
            "latency_p50_ms": self._percentile(0.50),
            "latency_p95_ms": self._percentile(0.95),
            "latency_p99_ms": self._percentile(0.99),
        }


class MetricsRegistry:
    """Singleton-like registry; stored on app.state.metrics."""

    def __init__(self) -> None:
        self.http = HttpMetrics()
        self._providers: dict[str, ProviderMetrics] = {}
        # Egress-block counter keyed by (provider, reason). Populated by
        # OpsecAwareClient on every blocked outbound body.
        self._egress_blocks: dict[tuple[str, str], int] = {}

    def provider(self, name: str) -> ProviderMetrics:
        if name not in self._providers:
            self._providers[name] = ProviderMetrics(provider=name)
        return self._providers[name]

    def record_egress_block(self, provider: str, reason: str) -> None:
        key = (provider, reason)
        self._egress_blocks[key] = self._egress_blocks.get(key, 0) + 1

    def egress_blocks(self) -> list[dict[str, Any]]:
        return [
            {"provider": p, "reason": r, "count": c}
            for (p, r), c in sorted(self._egress_blocks.items())
        ]

    def snapshot(self) -> dict[str, Any]:
        return {
            "http": self.http.snapshot(),
            "providers": {k: v.snapshot() for k, v in self._providers.items()},
            "egress_blocks": self.egress_blocks(),
        }
