"""Unit tests for Priority Score 2.0 — exploitability bonus (P2)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.priority import (
    EXPL_WEIGHT_NUCLEI,
    EXPL_WEIGHT_POC,
    compute_priority_factors,
    compute_priority_score,
)


def _now() -> datetime:
    return datetime.now(tz=UTC)


# ─────────────────────────────────── regression vs v1 ───────────────────────


class TestBackwardCompatibility:
    """Calling without the new flags must yield identical scores to v1."""

    def test_zero_score_unchanged(self):
        assert compute_priority_score(None, None, None, False, None) == 0

    def test_kev_only_unchanged(self):
        assert compute_priority_score(None, None, 0.0, True, None) == 25

    def test_critical_kev_recent_unchanged(self):
        # Same as v1: 25 + 25 + 10 = 60
        score = compute_priority_score(
            9.8, "CRITICAL", 0.0, True, _now() - timedelta(days=2)
        )
        assert score == 60


# ───────────────────────────────────── new bonus ────────────────────────────


class TestExploitabilityBonus:
    def test_only_poc_adds_5(self):
        score = compute_priority_score(
            None, None, 0.0, False, None,
            has_public_poc=True, has_nuclei_template=False,
        )
        assert score == EXPL_WEIGHT_POC == 5

    def test_only_nuclei_adds_8(self):
        score = compute_priority_score(
            None, None, 0.0, False, None,
            has_public_poc=False, has_nuclei_template=True,
        )
        assert score == EXPL_WEIGHT_NUCLEI == 8

    def test_both_flags_add_only_8_not_13(self):
        """Mutually-exclusive: presence of Nuclei wins, no double counting."""
        score = compute_priority_score(
            None, None, 0.0, False, None,
            has_public_poc=True, has_nuclei_template=True,
        )
        assert score == EXPL_WEIGHT_NUCLEI

    def test_capped_at_100_with_full_signals_and_template(self):
        # EPSS 0.99 (round 40) + CRITICAL 25 + KEV 25 + recent 10 + Nuclei 8 = 108 → cap 100
        score = compute_priority_score(
            9.8, "CRITICAL", 0.99, True, _now() - timedelta(days=1),
            has_public_poc=True, has_nuclei_template=True,
        )
        assert score == 100

    def test_no_bonus_when_both_flags_false(self):
        score_with_flags = compute_priority_score(
            7.5, "HIGH", 0.5, False, None,
            has_public_poc=False, has_nuclei_template=False,
        )
        score_without_kwargs = compute_priority_score(7.5, "HIGH", 0.5, False, None)
        assert score_with_flags == score_without_kwargs


# ──────────────────────────────────── factors ──────────────────────────────


class TestComputePriorityFactors:
    def test_all_zero(self):
        f = compute_priority_factors(None, None, None, False, None)
        assert f == {
            "epss_contribution": 0,
            "cvss_contribution": 0,
            "kev_contribution": 0,
            "recency_contribution": 0,
            "exploitability_contribution": 0,
        }

    def test_full_breakdown(self):
        f = compute_priority_factors(
            9.8, "CRITICAL", 0.5, True, _now() - timedelta(days=1),
            has_public_poc=True, has_nuclei_template=True,
        )
        assert f["epss_contribution"] == 20
        assert f["cvss_contribution"] == 25
        assert f["kev_contribution"] == 25
        assert f["recency_contribution"] == 10
        assert f["exploitability_contribution"] == 8  # Nuclei wins

    def test_poc_only_breakdown(self):
        f = compute_priority_factors(
            None, None, None, False, None,
            has_public_poc=True, has_nuclei_template=False,
        )
        assert f["exploitability_contribution"] == EXPL_WEIGHT_POC

    def test_factors_sum_match_score_under_cap(self):
        """When the raw sum is < 100, factors should sum to the same value."""
        score = compute_priority_score(
            5.0, "MEDIUM", 0.1, False, None,
            has_public_poc=True,
        )
        f = compute_priority_factors(
            5.0, "MEDIUM", 0.1, False, None,
            has_public_poc=True,
        )
        assert sum(f.values()) == score
