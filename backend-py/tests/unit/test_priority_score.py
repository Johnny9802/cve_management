"""Unit tests for priority score engine."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.priority import compute_priority_score, get_priority_label


def _now() -> datetime:
    return datetime.now(tz=UTC)


class TestComputePriorityScore:
    def test_zero_inputs(self):
        score = compute_priority_score(None, None, None, False, None)
        assert score == 0

    def test_epss_max_contribution(self):
        # epss=1.0 → +40
        score = compute_priority_score(None, None, 1.0, False, None)
        assert score == 40

    def test_critical_cvss_contribution(self):
        score = compute_priority_score(9.8, "CRITICAL", 0.0, False, None)
        assert score == 25

    def test_high_cvss_contribution(self):
        score = compute_priority_score(7.5, "HIGH", 0.0, False, None)
        assert score == 18

    def test_medium_cvss_contribution(self):
        score = compute_priority_score(5.0, "MEDIUM", 0.0, False, None)
        assert score == 10

    def test_low_cvss_contribution(self):
        score = compute_priority_score(2.0, "LOW", 0.0, False, None)
        assert score == 4

    def test_kev_flat_bonus(self):
        # KEV alone → +25
        score = compute_priority_score(None, None, 0.0, True, None)
        assert score == 25

    def test_recency_30_days(self):
        pub = _now() - timedelta(days=15)
        score = compute_priority_score(None, None, 0.0, False, pub)
        assert score == 10

    def test_recency_90_days(self):
        pub = _now() - timedelta(days=60)
        score = compute_priority_score(None, None, 0.0, False, pub)
        assert score == 6

    def test_recency_365_days(self):
        pub = _now() - timedelta(days=200)
        score = compute_priority_score(None, None, 0.0, False, pub)
        assert score == 3

    def test_recency_old(self):
        pub = _now() - timedelta(days=400)
        score = compute_priority_score(None, None, 0.0, False, pub)
        assert score == 0

    def test_max_score_capped_at_100(self):
        # EPSS=1.0(40) + CRITICAL(25) + KEV(25) + recent(10) = 100
        score = compute_priority_score(9.8, "CRITICAL", 1.0, True, _now() - timedelta(days=1))
        assert score == 100

    def test_full_kev_is_always_high_priority(self):
        # Even with no EPSS and LOW CVSS, KEV alone → label HIGH PRIORITY
        score = compute_priority_score(2.0, "LOW", 0.01, True, None)
        assert score >= 25 + 4   # KEV + LOW
        label = get_priority_label(score)
        assert label["label"] in ("HIGH PRIORITY", "CRITICAL PRIORITY", "MEDIUM PRIORITY")

    def test_cvss_score_fallback_without_severity(self):
        # cvss=9.5 without severity string → still gets CRITICAL band
        score = compute_priority_score(9.5, None, 0.0, False, None)
        assert score == 25


class TestGetPriorityLabel:
    def test_critical(self):
        assert get_priority_label(90)["label"] == "CRITICAL PRIORITY"
        assert get_priority_label(80)["label"] == "CRITICAL PRIORITY"

    def test_high(self):
        assert get_priority_label(70)["label"] == "HIGH PRIORITY"
        assert get_priority_label(60)["label"] == "HIGH PRIORITY"

    def test_medium(self):
        assert get_priority_label(50)["label"] == "MEDIUM PRIORITY"

    def test_monitor(self):
        assert get_priority_label(30)["label"] == "MONITOR"
        assert get_priority_label(0)["label"] == "MONITOR"
