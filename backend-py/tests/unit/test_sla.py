"""Unit tests for the SLA helper (P8)."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from app.services.sla import (
    AT_RISK_THRESHOLD_DAYS,
    SLA_DAYS,
    SLA_KEV_OVERRIDE,
    compute_due_date,
    compute_sla_state,
    days_overdue,
)


def _utc(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str).replace(tzinfo=timezone.utc)


# ─────────────────────────────────────────────────── due-date matrix


class TestComputeDueDate:
    def test_critical_default(self):
        pub = _utc("2026-01-01")
        assert compute_due_date(severity="CRITICAL", is_kev=False, published_at=pub) == \
            (pub + timedelta(days=SLA_DAYS["CRITICAL"])).date()

    def test_high_default(self):
        pub = _utc("2026-01-01")
        assert compute_due_date(severity="HIGH", is_kev=False, published_at=pub) == \
            (pub + timedelta(days=SLA_DAYS["HIGH"])).date()

    def test_medium_default(self):
        pub = _utc("2026-01-01")
        assert compute_due_date(severity="MEDIUM", is_kev=False, published_at=pub) == \
            (pub + timedelta(days=SLA_DAYS["MEDIUM"])).date()

    def test_low_default(self):
        pub = _utc("2026-01-01")
        assert compute_due_date(severity="LOW", is_kev=False, published_at=pub) == \
            (pub + timedelta(days=SLA_DAYS["LOW"])).date()

    def test_kev_overrides_severity(self):
        pub = _utc("2026-01-01")
        # Even LOW + KEV → 3 days from publish
        result = compute_due_date(severity="LOW", is_kev=True, published_at=pub)
        assert result == (pub + timedelta(days=SLA_KEV_OVERRIDE)).date()

    def test_unknown_severity_falls_back_to_medium(self):
        pub = _utc("2026-01-01")
        result = compute_due_date(severity=None, is_kev=False, published_at=pub)
        assert result == (pub + timedelta(days=SLA_DAYS["MEDIUM"])).date()

    def test_missing_published_uses_created(self):
        created = _utc("2026-01-15")
        result = compute_due_date(
            severity="HIGH",
            is_kev=False,
            published_at=None,
            created_at=created,
        )
        assert result == (created + timedelta(days=SLA_DAYS["HIGH"])).date()


# ─────────────────────────────────────────────────────── states


class TestComputeSlaState:
    def test_remediated_is_met(self):
        d = date.today() - timedelta(days=200)  # past due, but closed
        assert compute_sla_state(finding_status="remediated", due_date=d) == "met"

    def test_open_past_due_is_breached(self):
        d = date.today() - timedelta(days=5)
        assert compute_sla_state(finding_status="open", due_date=d) == "breached"

    def test_open_within_at_risk_window(self):
        d = date.today() + timedelta(days=AT_RISK_THRESHOLD_DAYS - 1)
        assert compute_sla_state(finding_status="open", due_date=d) == "at_risk"

    def test_open_far_in_future_is_on_track(self):
        d = date.today() + timedelta(days=AT_RISK_THRESHOLD_DAYS + 30)
        assert compute_sla_state(finding_status="open", due_date=d) == "on_track"

    def test_no_due_date_is_on_track(self):
        assert compute_sla_state(finding_status="in_review", due_date=None) == "on_track"


class TestDaysOverdue:
    def test_zero_when_not_breached(self):
        assert days_overdue(date.today() + timedelta(days=10)) == 0

    def test_correct_overdue_count(self):
        assert days_overdue(date.today() - timedelta(days=14)) == 14

    def test_none_due_date_is_zero(self):
        assert days_overdue(None) == 0
