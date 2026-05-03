"""Pydantic models for NVD 2.0 CVE format (used by VulnCheck NVD++ and NIST NVD API v2)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel


def _parse_dt(s: str) -> datetime:
    """Parse NVD ISO-8601 string to UTC-aware datetime."""
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class NvdCveRecord(BaseModel):
    """Parsed fields extracted from a single NVD 2.0 CVE object.

    raw_payload stores the full original dict so no information is discarded
    even if our parsing logic evolves.
    """

    cve_id: str
    published_at: datetime
    last_modified_at: datetime
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v2_score: float | None = None
    severity: str | None = None
    raw_payload: dict[str, Any]

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def from_nvd_cve(cls, cve: dict[str, Any]) -> "NvdCveRecord":
        """Parse from an NVD 2.0 inner CVE object.

        Accepts both:
        - Direct CVE object: {"id": "CVE-...", "published": "...", ...}
        - Wrapped:           {"cve": {"id": "CVE-...", ...}}
        """
        obj = cve.get("cve", cve)

        cvss_v3_score: float | None = None
        cvss_v3_vector: str | None = None
        severity: str | None = None
        cvss_v2_score: float | None = None

        metrics = obj.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
                severity = cvss_data.get("baseSeverity")
                break

        v2_entries = metrics.get("cvssMetricV2") or []
        if v2_entries:
            cvss_v2_score = v2_entries[0].get("cvssData", {}).get("baseScore")

        if not severity and cvss_v2_score is not None:
            if cvss_v2_score >= 7.0:
                severity = "HIGH"
            elif cvss_v2_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # Normalise severity to uppercase
        if severity:
            severity = severity.upper()

        return cls(
            cve_id=obj["id"],
            published_at=_parse_dt(obj["published"]),
            last_modified_at=_parse_dt(obj["lastModified"]),
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_score=cvss_v2_score,
            severity=severity,
            raw_payload=obj,
        )

    def to_row(self, source: str) -> tuple[Any, ...]:
        """Return an asyncpg-compatible row tuple for the cves upsert."""
        return (
            self.cve_id,
            source,
            json.dumps(self.raw_payload),
            self.cvss_v3_score,
            self.cvss_v3_vector,
            self.cvss_v2_score,
            self.severity,
            self.published_at,
            self.last_modified_at,
        )
