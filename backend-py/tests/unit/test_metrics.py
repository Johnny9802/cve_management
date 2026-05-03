"""Unit tests for the in-process metrics registry."""
from __future__ import annotations

import pytest

from app.core.metrics import HttpMetrics, MetricsRegistry, ProviderMetrics


class TestProviderMetrics:
    def test_initial_state_is_zero(self):
        m = ProviderMetrics(provider="nvd")
        assert m.requests_total == 0
        assert m.rate_limited_total == 0
        assert m.errors_total == 0

    def test_record_request_increments(self):
        m = ProviderMetrics(provider="nvd")
        m.record_request(0.5)
        assert m.requests_total == 1

    def test_record_rate_limited_increments(self):
        m = ProviderMetrics(provider="nvd")
        m.record_rate_limited()
        assert m.rate_limited_total == 1

    def test_record_error_increments(self):
        m = ProviderMetrics(provider="nvd")
        m.record_error()
        assert m.errors_total == 1

    def test_p95_none_when_few_samples(self):
        m = ProviderMetrics(provider="nvd")
        for _ in range(4):
            m.record_request(0.1)
        assert m._percentile(0.95) is None

    def test_p95_computed_with_enough_samples(self):
        m = ProviderMetrics(provider="nvd")
        for i in range(100):
            m.record_request(i / 100.0)  # 0.0 to 0.99 seconds
        p95 = m._percentile(0.95)
        assert p95 is not None
        assert p95 > 800  # ms: 95th percentile of 0..990ms range

    def test_snapshot_contains_all_fields(self):
        m = ProviderMetrics(provider="nvd")
        m.record_request(0.1)
        snap = m.snapshot()
        assert snap["provider"] == "nvd"
        assert "requests_total" in snap
        assert "rate_limited_total" in snap
        assert "errors_total" in snap
        assert "latency_p95_ms" in snap
        assert "sample_count" in snap

    def test_sliding_window_maxlen(self):
        m = ProviderMetrics(provider="test")
        for i in range(1500):
            m.record_request(float(i) / 1000)
        assert len(m._latencies_s) == 1000  # maxlen=1000


class TestHttpMetrics:
    def test_records_request(self):
        m = HttpMetrics()
        m.record(0.05, 200)
        assert m.requests_total == 1
        assert m.errors_5xx_total == 0

    def test_records_5xx(self):
        m = HttpMetrics()
        m.record(0.1, 500)
        assert m.errors_5xx_total == 1

    def test_4xx_not_counted_as_error(self):
        m = HttpMetrics()
        m.record(0.1, 404)
        assert m.errors_5xx_total == 0


class TestMetricsRegistry:
    def test_provider_lazily_created(self):
        reg = MetricsRegistry()
        m = reg.provider("vulncheck")
        assert m.provider == "vulncheck"

    def test_same_provider_returned_on_second_call(self):
        reg = MetricsRegistry()
        a = reg.provider("nvd")
        b = reg.provider("nvd")
        assert a is b

    def test_snapshot_structure(self):
        reg = MetricsRegistry()
        reg.provider("nvd").record_request(0.1)
        reg.http.record(0.05, 200)
        snap = reg.snapshot()
        assert "http" in snap
        assert "providers" in snap
        assert "nvd" in snap["providers"]
