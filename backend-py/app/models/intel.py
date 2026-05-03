"""Intel record — exploitability metadata returned by the vulnx provider.

The DB persists only the boolean summary fields (``has_public_poc``,
``has_nuclei_template``, ``exploitability_updated_at`` on table ``cves``).
The verbose lists (``poc_urls``, ``template_paths``) are returned through
the /api/cves/{id}/intel endpoint and never stored — keeping the DB schema
narrow and avoiding stale URL lists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class IntelRecord:
    cve_id: str
    has_public_poc: bool
    has_nuclei_template: bool
    poc_urls: list[str] = field(default_factory=list)
    template_paths: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def summary(self) -> dict[str, object]:
        """Compact dict used to update the ``cves`` row."""
        return {
            "has_public_poc": self.has_public_poc,
            "has_nuclei_template": self.has_nuclei_template,
            "exploitability_updated_at": self.fetched_at,
        }
