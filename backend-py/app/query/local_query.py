"""Tier 1 query — local PostgreSQL mirror.

All CVE lookups start here. Zero external calls, zero OpSec risk.
"""
from __future__ import annotations

import asyncpg
import structlog

from app.models.finding import FindingRow, QueryFilters, QueryResult

logger = structlog.get_logger(__name__)

_FINDINGS_SQL = """
    SELECT
        f.id               AS finding_id,
        f.product_id,
        f.cve_id,
        f.status,
        f.match_confidence,
        f.priority_score,
        f.assigned_to,
        f.due_date,
        c.cvss_v3_score,
        c.cvss_v3_vector,
        c.cvss_v2_score,
        c.severity,
        c.epss_score,
        c.epss_percentile,
        c.is_kev,
        c.kev_added_date,
        c.published_at,
        c.last_modified_at,
        c.raw_payload -> 'descriptions' -> 0 ->> 'value' AS description
    FROM findings f
    JOIN cves c ON c.cve_id = f.cve_id
    WHERE f.product_id = $1
      AND ($2::text[]  IS NULL OR f.status          = ANY($2))
      AND ($3::text    IS NULL OR c.severity         = $3)
      AND ($4::numeric IS NULL OR c.cvss_v3_score   >= $4)
      AND ($5::numeric IS NULL OR c.epss_score       >= $5)
      AND ($6::text    IS NULL OR f.match_confidence = $6)
    ORDER BY f.priority_score DESC NULLS LAST, c.cvss_v3_score DESC NULLS LAST
    LIMIT $7 OFFSET $8
"""

_COUNT_SQL = """
    SELECT COUNT(*)
    FROM findings f
    JOIN cves c ON c.cve_id = f.cve_id
    WHERE f.product_id = $1
      AND ($2::text[]  IS NULL OR f.status          = ANY($2))
      AND ($3::text    IS NULL OR c.severity         = $3)
      AND ($4::numeric IS NULL OR c.cvss_v3_score   >= $4)
      AND ($5::numeric IS NULL OR c.epss_score       >= $5)
      AND ($6::text    IS NULL OR f.match_confidence = $6)
"""


def _row_to_finding(row: asyncpg.Record) -> FindingRow:
    return FindingRow(
        finding_id=row["finding_id"],
        product_id=row["product_id"],
        cve_id=row["cve_id"],
        status=row["status"],
        match_confidence=row["match_confidence"],
        priority_score=float(row["priority_score"]) if row["priority_score"] is not None else None,
        assigned_to=row["assigned_to"],
        due_date=row["due_date"],
        cvss_v3_score=float(row["cvss_v3_score"]) if row["cvss_v3_score"] is not None else None,
        cvss_v3_vector=row["cvss_v3_vector"],
        cvss_v2_score=float(row["cvss_v2_score"]) if row["cvss_v2_score"] is not None else None,
        severity=row["severity"],
        epss_score=float(row["epss_score"]) if row["epss_score"] is not None else None,
        epss_percentile=float(row["epss_percentile"]) if row["epss_percentile"] is not None else None,
        is_kev=bool(row["is_kev"]),
        kev_added_date=row["kev_added_date"],
        published_at=row["published_at"],
        last_modified_at=row["last_modified_at"],
        description=row["description"],
    )


def _filter_args(product_id: int, filters: QueryFilters) -> tuple:
    return (
        product_id,
        filters.statuses or None,
        filters.severity,
        filters.min_cvss,
        filters.min_epss,
        filters.confidence,
    )


async def query_findings(
    pool: asyncpg.Pool,
    product_id: int,
    filters: QueryFilters,
) -> QueryResult:
    offset = (filters.page - 1) * filters.page_size
    base_args = _filter_args(product_id, filters)

    async with pool.acquire() as conn:
        count_row = await conn.fetchrow(_COUNT_SQL, *base_args)
        total = int(count_row[0]) if count_row else 0

        data_rows = await conn.fetch(
            _FINDINGS_SQL, *base_args, filters.page_size, offset
        )

    findings = [_row_to_finding(r) for r in data_rows]
    logger.debug(
        "local_query.done",
        product_id=product_id,
        total=total,
        returned=len(findings),
        page=filters.page,
    )
    return QueryResult(
        findings=findings,
        total=total,
        page=filters.page,
        page_size=filters.page_size,
        source="local",
    )


async def get_product_cpe(pool: asyncpg.Pool, product_id: int) -> str | None:
    """Return the normalized CPE for a product, if resolved."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT normalized_cpe FROM products WHERE id = $1", product_id
        )
    return row["normalized_cpe"] if row else None
