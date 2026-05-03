"""Async token bucket rate limiter (single-process, asyncio.Lock-based).

Each provider gets its own TokenBucket instance. Use build_governors() to
get a pre-configured registry keyed by provider name.
"""
import asyncio
import time
from dataclasses import dataclass, field

import structlog

from app.core.config import Settings

logger = structlog.get_logger(__name__)


@dataclass
class TokenBucket:
    """Token bucket rate limiter.

    capacity    — max tokens (controls burst)
    refill_rate — tokens added per second
    """

    name: str
    capacity: float
    refill_rate: float  # tokens / second
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._metrics: "ProviderMetrics | None" = None  # type: ignore[name-defined]

    def _refill(self) -> None:
        now = time.monotonic()
        added = (now - self._last_refill) * self.refill_rate
        self._tokens = min(self.capacity, self._tokens + added)
        self._last_refill = now

    async def acquire(self, cost: float = 1.0) -> None:
        """Block until `cost` tokens are available, then consume them."""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= cost:
                    self._tokens -= cost
                    return
                wait = (cost - self._tokens) / self.refill_rate

            logger.debug(
                "rate_governor.wait",
                provider=self.name,
                wait_s=round(wait, 2),
                tokens=round(self._tokens, 2),
            )
            if self._metrics:
                self._metrics.record_rate_limited()
            await asyncio.sleep(wait)

    def attach_metrics(self, metrics: "ProviderMetrics") -> None:  # type: ignore[name-defined]
        self._metrics = metrics

    @property
    def available(self) -> float:
        """Current token count (snapshot, not thread-safe)."""
        return self._tokens


def build_governors(settings: Settings) -> dict[str, TokenBucket]:
    """Build per-provider TokenBucket instances based on configured limits."""
    has_nvd_key = bool(settings.nvd_api_key)

    return {
        # NVD: 5/30s without key, 50/30s with key
        "nvd": TokenBucket(
            name="nvd",
            capacity=50.0 if has_nvd_key else 5.0,
            refill_rate=50 / 30 if has_nvd_key else 5 / 30,
        ),
        # VulnCheck: conservative default for free tier (10 req/60s)
        # VulnCheck S3 downloads bypass rate limiting entirely
        "vulncheck": TokenBucket(
            name="vulncheck",
            capacity=10.0,
            refill_rate=10.0 / 60.0,
        ),
        # CIRCL: 20 000 req/day hard limit → ~0.231 req/s; burst 20
        "circl": TokenBucket(
            name="circl",
            capacity=20.0,
            refill_rate=settings.circl_daily_limit / 86400,
        ),
        # EPSS: generous, batch up to 100 CVE IDs per call
        "epss": TokenBucket(
            name="epss",
            capacity=10.0,
            refill_rate=1.0,
        ),
        # CISA KEV: static JSON, polled every 6h
        "kev": TokenBucket(
            name="kev",
            capacity=1.0,
            refill_rate=1.0 / (settings.kev_refresh_interval_hours * 3600),
        ),
        # vulnx (ProjectDiscovery): conservative for free tier; daily-budget
        # enforcement is layered on top in VulnxClient via daily counter.
        # Default ~5 req/s burst, 2 req/s sustained (≈170k req/day theoretical
        # but the daily_limit caps actual usage).
        "vulnx": TokenBucket(
            name="vulnx",
            capacity=5.0,
            refill_rate=2.0,
        ),
    }
