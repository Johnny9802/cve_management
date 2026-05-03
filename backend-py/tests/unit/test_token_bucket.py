"""Unit tests for the TokenBucket rate limiter."""
from __future__ import annotations

import asyncio
import time

import pytest

from app.ingestion.rate_governor import TokenBucket


@pytest.fixture
def bucket_10_per_s() -> TokenBucket:
    return TokenBucket(name="test", capacity=10.0, refill_rate=10.0)


@pytest.fixture
def bucket_1_per_s() -> TokenBucket:
    return TokenBucket(name="test", capacity=1.0, refill_rate=1.0)


class TestTokenBucketAcquire:
    @pytest.mark.asyncio
    async def test_immediate_acquire_within_capacity(self, bucket_10_per_s: TokenBucket):
        t0 = time.monotonic()
        for _ in range(10):
            await bucket_10_per_s.acquire()
        elapsed = time.monotonic() - t0
        # All 10 tokens immediately available — should be near-instant
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_acquire_depletes_tokens(self, bucket_10_per_s: TokenBucket):
        initial_tokens = bucket_10_per_s._tokens
        await bucket_10_per_s.acquire(cost=5.0)
        assert bucket_10_per_s._tokens < initial_tokens

    @pytest.mark.asyncio
    async def test_acquire_blocks_when_empty(self, bucket_1_per_s: TokenBucket):
        # Drain the bucket
        await bucket_1_per_s.acquire(cost=1.0)
        assert bucket_1_per_s._tokens < 0.5

        # Next acquire should block (takes ~1s to refill 1 token)
        t0 = time.monotonic()
        await bucket_1_per_s.acquire(cost=1.0)
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.5, f"Expected ≥0.5s wait, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_concurrent_acquires_serialized(self, bucket_10_per_s: TokenBucket):
        """10 concurrent acquires on a 10-token bucket should all complete."""
        tasks = [asyncio.create_task(bucket_10_per_s.acquire()) for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        errors = [r for r in results if isinstance(r, Exception)]
        assert errors == []

    @pytest.mark.asyncio
    async def test_refill_over_time(self):
        """Bucket refills at refill_rate tokens/second."""
        bucket = TokenBucket(name="test", capacity=2.0, refill_rate=10.0)
        # Drain completely
        await bucket.acquire(cost=2.0)
        assert bucket._tokens < 0.1

        # Wait ~100ms → should get ~1 token back (10 t/s × 0.1s = 1.0)
        await asyncio.sleep(0.12)
        bucket._refill()
        assert bucket._tokens >= 0.8

    @pytest.mark.asyncio
    async def test_tokens_never_exceed_capacity(self):
        bucket = TokenBucket(name="test", capacity=5.0, refill_rate=100.0)
        await asyncio.sleep(0.2)  # let it overfill if broken
        bucket._refill()
        assert bucket._tokens <= 5.0 + 0.01  # float tolerance


class TestTokenBucketAvailableProperty:
    def test_available_starts_at_capacity(self):
        bucket = TokenBucket(name="test", capacity=5.0, refill_rate=1.0)
        assert bucket.available == 5.0


class TestTokenBucketMetricsAttach:
    @pytest.mark.asyncio
    async def test_rate_limited_metric_recorded(self):
        from app.core.metrics import ProviderMetrics
        bucket = TokenBucket(name="nvd", capacity=1.0, refill_rate=100.0)
        pm = ProviderMetrics(provider="nvd")
        bucket.attach_metrics(pm)

        # Drain immediately, next acquire will sleep briefly and call record_rate_limited
        await bucket.acquire(1.0)
        # Next call needs tokens — rate_limited should be recorded during the wait
        task = asyncio.create_task(bucket.acquire(1.0))
        await asyncio.sleep(0.02)  # let the bucket detect empty state
        await task
        # record_rate_limited was called at least once
        assert pm.rate_limited_total >= 1
