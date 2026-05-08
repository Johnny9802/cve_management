"""Circuit breaker for external API providers.

States:
  CLOSED    — normal operation, failures counted
  OPEN      — fast-fail for recovery_timeout seconds
  HALF_OPEN — one probe allowed; success → CLOSED, failure → OPEN
"""
import asyncio
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any, TypeVar

import structlog

logger = structlog.get_logger(__name__)
T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit is open."""


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._failures = 0
        self._state = CircuitState.CLOSED
        self._open_until = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def call(
        self,
        fn: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if time.monotonic() < self._open_until:
                    raise CircuitOpenError(
                        f"Circuit '{self.name}' is OPEN "
                        f"(retry in {self._open_until - time.monotonic():.0f}s)"
                    )
                # Transition to half-open for a probe
                self._state = CircuitState.HALF_OPEN
                logger.info("circuit_breaker.half_open", name=self.name)

        try:
            result = await fn(*args, **kwargs)
            await self._on_success()
            return result
        except CircuitOpenError:
            raise
        except Exception:
            await self._on_failure()
            raise

    async def _on_success(self) -> None:
        async with self._lock:
            if self._state in (CircuitState.HALF_OPEN, CircuitState.CLOSED):
                if self._failures > 0:
                    logger.info("circuit_breaker.recovered", name=self.name)
                self._failures = 0
                self._state = CircuitState.CLOSED

    async def _on_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self._failure_threshold:
                self._state = CircuitState.OPEN
                self._open_until = time.monotonic() + self._recovery_timeout
                logger.warning(
                    "circuit_breaker.opened",
                    name=self.name,
                    failures=self._failures,
                    recovery_in_s=self._recovery_timeout,
                )


    @property
    def status_snapshot(self) -> dict:
        return {
            "name": self.name,
            "state": self._state.value,
            "failures": self._failures,
            "threshold": self._failure_threshold,
            "open_until_s": max(0.0, round(self._open_until - time.monotonic(), 1))
            if self._state == CircuitState.OPEN
            else None,
        }


def build_circuit_breakers() -> dict[str, CircuitBreaker]:
    return {
        "vulncheck": CircuitBreaker("vulncheck", failure_threshold=5, recovery_timeout=60.0),
        "nvd": CircuitBreaker("nvd", failure_threshold=5, recovery_timeout=120.0),
        "circl": CircuitBreaker("circl", failure_threshold=3, recovery_timeout=300.0),
        "epss": CircuitBreaker("epss", failure_threshold=3, recovery_timeout=60.0),
        "kev": CircuitBreaker("kev", failure_threshold=3, recovery_timeout=3600.0),
        # vulnx: relatively short recovery — exploitability data is
        # opportunistic, no point holding the circuit open for hours.
        "vulnx": CircuitBreaker("vulnx", failure_threshold=5, recovery_timeout=180.0),
    }
