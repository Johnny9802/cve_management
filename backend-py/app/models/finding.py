"""Response models for the query layer."""
from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel


class QueryFilters(BaseModel):
    statuses: list[str] | None = None       # filter by finding status
    severity: str | None = None             # CRITICAL | HIGH | MEDIUM | LOW | NONE
    min_cvss: float | None = None
    min_epss: float | None = None
    confidence: str | None = None           # certain | uncertain
    page: int = 1
    page_size: int = 50


class FindingRow(BaseModel):
    finding_id: int
    product_id: int
    cve_id: str
    status: str
    match_confidence: str | None
    priority_score: float | None
    assigned_to: str | None
    due_date: date | None
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    cvss_v2_score: float | None
    severity: str | None
    epss_score: float | None
    epss_percentile: float | None
    is_kev: bool
    kev_added_date: date | None
    published_at: datetime
    last_modified_at: datetime
    description: str | None


class QueryResult(BaseModel):
    findings: list[FindingRow]
    total: int
    page: int
    page_size: int
    source: Literal["local", "local+circl", "local_only"]
