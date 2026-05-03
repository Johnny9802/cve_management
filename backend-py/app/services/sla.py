"""SLA matrix + due-date / state computation (P8).

Default SLA in days from CVE ``published_at``:

  CRITICAL : 7
  HIGH     : 30
  MEDIUM   : 90
  LOW      : 180

KEV override: 3 days regardless of severity.
Fallback when ``published_at`` is missing: use ``created_at`` of the
finding row.

States derived for the dashboards (matching the brief):
  met       — finding closed (remediated, closed, false_positive)
  breached  — open / in_review / planned past the due date
  at_risk   — within 7 days of the due date
  on_track  — anything else
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Literal

SLA_DAYS: dict[str, int] = {
    "CRITICAL": 7,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180,
}
SLA_KEV_OVERRIDE = 3
DEFAULT_SLA_DAYS = SLA_DAYS["MEDIUM"]
AT_RISK_THRESHOLD_DAYS = 7

SlaState = Literal["met", "breached", "at_risk", "on_track"]


def compute_due_date(
    *,
    severity: str | None,
    is_kev: bool,
    published_at: datetime | None,
    created_at: datetime | None = None,
) -> date:
    """Return the SLA due date for a finding.

    Falls back to ``created_at`` if ``published_at`` is None. If both are
    None, fallback to ``today()`` (defensive — should not happen because
    findings always have created_at).
    """
    if is_kev:
        days = SLA_KEV_OVERRIDE
    else:
        days = SLA_DAYS.get((severity or "").upper(), DEFAULT_SLA_DAYS)
    base = published_at or created_at or datetime.now(tz=timezone.utc)
    if not isinstance(base, datetime):
        base = datetime(base.year, base.month, base.day, tzinfo=timezone.utc)
    elif base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return (base + timedelta(days=days)).date()


def compute_sla_state(
    *,
    finding_status: str,
    due_date: date | None,
    today: date | None = None,
) -> SlaState:
    today = today or datetime.now(tz=timezone.utc).date()
    if finding_status in {"remediated", "closed", "false_positive"}:
        return "met"
    if due_date is None:
        return "on_track"
    if due_date < today:
        return "breached"
    if (due_date - today).days <= AT_RISK_THRESHOLD_DAYS:
        return "at_risk"
    return "on_track"


def days_overdue(due_date: date | None, today: date | None = None) -> int:
    today = today or datetime.now(tz=timezone.utc).date()
    if due_date is None or due_date >= today:
        return 0
    return (today - due_date).days
