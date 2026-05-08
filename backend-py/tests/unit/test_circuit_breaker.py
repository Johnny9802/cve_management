"""FSM coverage for the per-provider CircuitBreaker (Sprint 2 — S2.9).

Closes test-coverage gap TST-02 from the production-readiness review:
the circuit breaker is the only thing between an external provider's
flaky window and our entire ingestion pipeline melting down, but it
had zero direct tests.

We use ``time.monotonic`` indirection: the breaker reads the wall via
``time.monotonic()`` only to compute ``open_until``. Each test patches
it with a small ``Clock`` helper so recovery_timeout assertions don't
depend on real wall-clock sleeps.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from app.ingestion.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    build_circuit_breakers,
)


class Clock:
    """Stand-in for ``time.monotonic`` we can advance from the test."""

    def __init__(self) -> None:
        self.t = 1_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    c = Clock()
    monkeypatch.setattr("app.ingestion.circuit_breaker.time.monotonic", c)
    return c


async def _ok() -> str:
    return "ok"


def _failing(exc: type[BaseException] = RuntimeError) -> Callable[[], Awaitable[Any]]:
    async def _f() -> Any:
        raise exc("upstream boom")

    return _f


# ────────────────────────────────────────────────────── basic states


@pytest.mark.asyncio
async def test_starts_closed():
    cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60)
    assert cb.state is CircuitState.CLOSED
    assert cb.status_snapshot["failures"] == 0


@pytest.mark.asyncio
async def test_success_keeps_circuit_closed_and_resets_failures(clock):
    cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60)

    # One failure, then a success → counter resets.
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    assert cb.status_snapshot["failures"] == 1

    result = await cb.call(_ok)
    assert result == "ok"
    assert cb.state is CircuitState.CLOSED
    assert cb.status_snapshot["failures"] == 0


@pytest.mark.asyncio
async def test_threshold_breach_opens_circuit(clock):
    cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60)

    for _ in range(2):
        with pytest.raises(RuntimeError):
            await cb.call(_failing())
    assert cb.state is CircuitState.CLOSED  # below threshold

    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    assert cb.state is CircuitState.OPEN
    assert cb.status_snapshot["open_until_s"] == pytest.approx(60.0, abs=0.5)


# ────────────────────────────────────────────────────── OPEN behaviour


@pytest.mark.asyncio
async def test_open_circuit_fast_fails_without_calling_fn(clock):
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=60)
    # Trip it.
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    assert cb.state is CircuitState.OPEN

    called = {"n": 0}

    async def _spy() -> str:
        called["n"] += 1
        return "should-not-run"

    with pytest.raises(CircuitOpenError):
        await cb.call(_spy)
    assert called["n"] == 0  # never reached the function


@pytest.mark.asyncio
async def test_open_until_countdown_decreases_with_clock(clock):
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=60)
    with pytest.raises(RuntimeError):
        await cb.call(_failing())

    snap0 = cb.status_snapshot
    clock.advance(20)
    snap1 = cb.status_snapshot
    assert snap0["open_until_s"] > snap1["open_until_s"]


# ────────────────────────────────────────────────────── HALF_OPEN behaviour


@pytest.mark.asyncio
async def test_recovery_timeout_promotes_to_half_open_then_closed_on_success(clock):
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=30)
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    assert cb.state is CircuitState.OPEN

    # Past the recovery window, the next call probes (HALF_OPEN) and
    # on success collapses to CLOSED.
    clock.advance(31)
    result = await cb.call(_ok)
    assert result == "ok"
    assert cb.state is CircuitState.CLOSED
    assert cb.status_snapshot["failures"] == 0


@pytest.mark.asyncio
async def test_half_open_failure_reopens_circuit(clock):
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=30)
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    assert cb.state is CircuitState.OPEN

    clock.advance(31)

    # The probe call fails — circuit must re-open and not stay HALF_OPEN.
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    assert cb.state is CircuitState.OPEN
    assert cb.status_snapshot["open_until_s"] is not None


@pytest.mark.asyncio
async def test_half_open_open_until_resets_on_failure(clock):
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=30)
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    clock.advance(31)
    snap_before = cb.status_snapshot
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    snap_after = cb.status_snapshot
    # After the failed probe, the open window has been refreshed.
    assert snap_after["open_until_s"] >= snap_before["open_until_s"]


# ────────────────────────────────────────────────────── snapshot + factory


@pytest.mark.asyncio
async def test_snapshot_shape_when_closed():
    cb = CircuitBreaker("test", failure_threshold=5, recovery_timeout=60)
    snap = cb.status_snapshot
    assert snap == {
        "name": "test",
        "state": "closed",
        "failures": 0,
        "threshold": 5,
        "open_until_s": None,
    }


@pytest.mark.asyncio
async def test_snapshot_shape_when_open(clock):
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=42)
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    snap = cb.status_snapshot
    assert snap["state"] == "open"
    assert snap["open_until_s"] == pytest.approx(42.0, abs=0.5)


def test_build_circuit_breakers_returns_one_per_provider():
    cbs = build_circuit_breakers()
    assert set(cbs) == {"vulncheck", "nvd", "circl", "epss", "kev", "vulnx"}
    for name, cb in cbs.items():
        assert cb.name == name
        assert cb.state is CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuitopenerror_is_not_counted_as_provider_failure(clock):
    """A CircuitOpenError raised by the breaker itself must NOT bump
    the failure counter — otherwise calls during the OPEN window would
    keep extending the window indefinitely."""
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=60)
    with pytest.raises(RuntimeError):
        await cb.call(_failing())
    assert cb.status_snapshot["failures"] == 1

    # Five fast-fails while OPEN — failure counter must not move.
    for _ in range(5):
        with pytest.raises(CircuitOpenError):
            await cb.call(_ok)
    assert cb.status_snapshot["failures"] == 1
