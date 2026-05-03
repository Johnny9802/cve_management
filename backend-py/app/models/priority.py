"""Priority score engine — port of priority.service.js.

Score 0-100 built from 5 signals (P2 — Priority Score 2.0):
  EPSS (0-40)             — exploitation probability (FIRST.org ML model)
  CVSS  (0-25)            — technical severity bands
  KEV   (0-25)            — confirmed active exploitation (CISA)
  Recency (0-10)          — newer CVEs face less mature patch coverage
  Exploitability (0-8)    — public PoC / Nuclei template availability (P1+P2)

Backward compatibility: the new ``has_public_poc`` and
``has_nuclei_template`` parameters default to ``False``. Existing callers
continue to receive identical scores; the bonus only kicks in when the
exploitability columns on ``cves`` are populated by the vulnx refresh job.

Weighting rationale: PoC/template indicate *technical capability* of
exploitation, not *active exploitation in the wild*. The maximum bonus
(8) is therefore strictly less than KEV (+25) and EPSS-at-max (+40). The
two flags are mutually exclusive: if both are present we award 8 (not
13) so a Nuclei template never "double counts" the underlying PoC.
"""
from __future__ import annotations

from datetime import datetime, timezone


# Public weights — exposed so ``factor breakdown`` in /api/cves/{id}/intel
# can label contributions without re-deriving constants.
EXPL_WEIGHT_POC = 5
EXPL_WEIGHT_NUCLEI = 8
KEV_WEIGHT = 25
EPSS_WEIGHT_MAX = 40
RECENCY_WEIGHT_MAX = 10


def compute_priority_score(
    cvss_score: float | None,
    severity: str | None,
    epss_score: float | None,
    is_kev: bool,
    published_at: datetime | None,
    has_public_poc: bool = False,
    has_nuclei_template: bool = False,
) -> int:
    score = 0

    # 1. EPSS (0-40)
    epss = float(epss_score or 0.0)
    score += round(epss * EPSS_WEIGHT_MAX)

    # 2. CVSS severity (0-25)
    cvss = float(cvss_score or 0.0)
    sev = (severity or "").upper()
    if sev == "CRITICAL" or cvss >= 9.0:
        score += 25
    elif sev == "HIGH" or cvss >= 7.0:
        score += 18
    elif sev == "MEDIUM" or cvss >= 4.0:
        score += 10
    elif sev == "LOW" or cvss > 0:
        score += 4

    # 3. CISA KEV (flat +25)
    if is_kev:
        score += KEV_WEIGHT

    # 4. Recency (0-10)
    if published_at:
        now = datetime.now(tz=timezone.utc)
        pub = published_at if published_at.tzinfo else published_at.replace(tzinfo=timezone.utc)
        age_days = (now - pub).days
        if age_days <= 30:
            score += 10
        elif age_days <= 90:
            score += 6
        elif age_days <= 365:
            score += 3

    # 5. Exploitability (0-8) — mutually exclusive bonus.
    if has_nuclei_template:
        score += EXPL_WEIGHT_NUCLEI
    elif has_public_poc:
        score += EXPL_WEIGHT_POC

    return min(100, max(0, score))


def compute_priority_factors(
    cvss_score: float | None,
    severity: str | None,
    epss_score: float | None,
    is_kev: bool,
    published_at: datetime | None,
    has_public_poc: bool = False,
    has_nuclei_template: bool = False,
) -> dict[str, int]:
    """Return the per-signal contributions used by ``compute_priority_score``.

    The sum of the returned values is then capped at 100 (matching the
    main scorer). Useful for the /api/cves/{id}/intel ``priority.factors``
    block — UI can render a stack chart explaining the score.
    """
    contributions: dict[str, int] = {
        "epss_contribution": 0,
        "cvss_contribution": 0,
        "kev_contribution": 0,
        "recency_contribution": 0,
        "exploitability_contribution": 0,
    }

    epss = float(epss_score or 0.0)
    contributions["epss_contribution"] = round(epss * EPSS_WEIGHT_MAX)

    cvss = float(cvss_score or 0.0)
    sev = (severity or "").upper()
    if sev == "CRITICAL" or cvss >= 9.0:
        contributions["cvss_contribution"] = 25
    elif sev == "HIGH" or cvss >= 7.0:
        contributions["cvss_contribution"] = 18
    elif sev == "MEDIUM" or cvss >= 4.0:
        contributions["cvss_contribution"] = 10
    elif sev == "LOW" or cvss > 0:
        contributions["cvss_contribution"] = 4

    if is_kev:
        contributions["kev_contribution"] = KEV_WEIGHT

    if published_at:
        now = datetime.now(tz=timezone.utc)
        pub = (
            published_at
            if published_at.tzinfo
            else published_at.replace(tzinfo=timezone.utc)
        )
        age_days = (now - pub).days
        if age_days <= 30:
            contributions["recency_contribution"] = 10
        elif age_days <= 90:
            contributions["recency_contribution"] = 6
        elif age_days <= 365:
            contributions["recency_contribution"] = 3

    if has_nuclei_template:
        contributions["exploitability_contribution"] = EXPL_WEIGHT_NUCLEI
    elif has_public_poc:
        contributions["exploitability_contribution"] = EXPL_WEIGHT_POC

    return contributions


def get_priority_label(score: int) -> dict[str, str]:
    if score >= 80:
        return {"label": "CRITICAL PRIORITY", "color": "red"}
    if score >= 60:
        return {"label": "HIGH PRIORITY", "color": "orange"}
    if score >= 40:
        return {"label": "MEDIUM PRIORITY", "color": "yellow"}
    return {"label": "MONITOR", "color": "blue"}
