"""Unit tests for enrichment logic (pure function behaviour, no I/O)."""
from __future__ import annotations

import json
from datetime import date

import pytest

from app.ingestion.enrichment import EnrichResult
from app.ingestion.epss_client import EpssScore

# ------------------------------------------------------------------ #
# EpssScore NamedTuple                                                 #
# ------------------------------------------------------------------ #

def test_epss_score_fields() -> None:
    s = EpssScore(cve_id="CVE-2024-0001", score=0.75, percentile=0.92)
    assert s.cve_id == "CVE-2024-0001"
    assert s.score == 0.75
    assert s.percentile == 0.92


# ------------------------------------------------------------------ #
# EnrichResult                                                         #
# ------------------------------------------------------------------ #

def test_enrich_result_fields() -> None:
    r = EnrichResult(job="epss_refresh", updated=50, skipped=10, errors=0, duration_ms=1234)
    assert r.updated == 50
    assert r.skipped == 10
    assert r.errors == 0
    assert r.duration_ms == 1234


# ------------------------------------------------------------------ #
# KEV catalog date parsing (via KevClient._fetch mocked)              #
# ------------------------------------------------------------------ #

def test_kev_date_parsing_isoformat() -> None:
    """date.fromisoformat covers the YYYY-MM-DD format CISA uses."""
    d = date.fromisoformat("2021-12-10")
    assert d == date(2021, 12, 10)


def test_kev_bad_date_raises_value_error() -> None:
    with pytest.raises(ValueError):
        date.fromisoformat("not-a-date")


# ------------------------------------------------------------------ #
# EPSS cache key format                                                #
# ------------------------------------------------------------------ #

def test_epss_cache_key_format() -> None:
    cve_id = "CVE-2024-12345"
    key = f"epss:{cve_id}"
    assert key == "epss:CVE-2024-12345"


def test_epss_cache_value_roundtrip() -> None:
    score = EpssScore("CVE-2024-0001", 0.85, 0.95)
    serialized = json.dumps({"epss": score.score, "percentile": score.percentile})
    parsed = json.loads(serialized)
    assert float(parsed["epss"]) == pytest.approx(0.85)
    assert float(parsed["percentile"]) == pytest.approx(0.95)
