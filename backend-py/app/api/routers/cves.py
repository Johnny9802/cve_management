"""CVEs router — /api/cves

Field name compatibility with Node.js frontend:
  `in_cisa_kev`   = alias for is_kev
  `description`   = extracted from raw_payload inline in SQL
  `priority_score`= from findings join when product_id filter is active
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/cves", tags=["cves"])

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_VALID_SORTS = {"priority_score", "cvss_v3_score", "epss_score", "published_at", "cve_id"}


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


def _row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    d = dict(row)
    if "is_kev" in d:
        d["in_cisa_kev"] = d.pop("is_kev")
    return d


def _escape_csv(v: Any) -> str:
    if v is None:
        return ""
    s = str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    s = s.replace('"', '""')
    return f'"{s}"' if any(ch in s for ch in (",", '"', "\n")) else s


# ── routes ────────────────────────────────────────────────────────────────────

@router.get("/export")
async def export_csv(
    pool: asyncpg.Pool = Depends(_get_pool),
    product_id: int | None = None,
    severity: str | None = None,
    kev: str | None = None,
    min_epss: float | None = None,
    min_priority: int | None = None,
    keyword: str | None = None,
    year: int | None = None,
) -> Response:
    conditions: list[str] = []
    args: list[Any] = []
    p = 1
    join = "JOIN findings f ON f.cve_id = c.cve_id" if product_id else ""

    if product_id:
        conditions.append(f"f.product_id = ${p}"); args.append(product_id); p += 1
    if severity:
        conditions.append(f"c.severity = ANY(${p})")
        args.append([s.strip().upper() for s in severity.split(",")]); p += 1
    if kev == "true":
        conditions.append("c.is_kev = TRUE")
    if min_epss is not None:
        conditions.append(f"c.epss_score >= ${p}"); args.append(min_epss); p += 1
    if min_priority is not None and product_id:
        conditions.append(f"f.priority_score >= ${p}"); args.append(min_priority); p += 1
    if year is not None:
        conditions.append(f"EXTRACT(YEAR FROM c.published_at) = ${p}"); args.append(year); p += 1
    if keyword:
        # Search both CVE ID and description (from raw_payload)
        conditions.append(
            f"(c.cve_id ILIKE ${p} OR c.raw_payload->'descriptions'->0->>'value' ILIKE ${p+1})"
        )
        args.append(f"%{keyword}%")
        args.append(f"%{keyword}%")
        p += 2

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    rows = await pool.fetch(
        f"""
        SELECT DISTINCT c.cve_id, c.severity, c.cvss_v3_score, c.cvss_v2_score,
               c.epss_score, c.epss_percentile, c.is_kev, c.kev_added_date,
               c.published_at, c.last_modified_at,
               c.raw_payload->'descriptions'->0->>'value' AS description
        FROM cves c {join} {where}
        ORDER BY c.cve_id LIMIT 10000
        """, *args,
    )

    hdrs = ["CVE ID","Severity","CVSS v3","CVSS v2","EPSS %","EPSS Pct",
            "KEV","KEV Date","Published","Last Modified","Description"]
    lines = [",".join(hdrs)]
    for r in rows:
        epss = f"{float(r['epss_score'])*100:.4f}%" if r["epss_score"] is not None else ""
        epss_p = f"{float(r['epss_percentile'])*100:.2f}%" if r["epss_percentile"] is not None else ""
        lines.append(",".join([
            _escape_csv(r["cve_id"]), _escape_csv(r["severity"]),
            _escape_csv(r["cvss_v3_score"]), _escape_csv(r["cvss_v2_score"]),
            epss, epss_p,
            "YES" if r["is_kev"] else "NO", _escape_csv(r["kev_added_date"]),
            _escape_csv(r["published_at"].date() if r["published_at"] else None),
            _escape_csv(r["last_modified_at"].date() if r["last_modified_at"] else None),
            _escape_csv(r["description"]),
        ]))

    filename = f"cve-export-{datetime.now(tz=timezone.utc).date()}.csv"
    return Response(
        content="﻿" + "\n".join(lines),  # BOM for Excel
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("")
async def list_cves(
    pool: asyncpg.Pool = Depends(_get_pool),
    product_id: int | None = None,
    severity: str | None = None,
    kev: str | None = None,
    min_epss: float | None = None,
    max_epss: float | None = None,
    min_priority: int | None = None,
    keyword: str | None = None,
    year: int | None = None,
    sort: str = "priority_score",
    order: str = "desc",
    page: int = 1,
    limit: int = 50,
) -> dict:
    page = max(1, page)
    limit = min(200, max(1, limit))
    offset = (page - 1) * limit
    sort_col = sort if sort in _VALID_SORTS else "priority_score"
    sort_dir = "ASC" if order.lower() == "asc" else "DESC"

    has_product = product_id is not None
    join = "JOIN findings f ON f.cve_id = c.cve_id AND f.product_id = $1" if has_product else ""
    base_args: list[Any] = [product_id] if has_product else []
    p = len(base_args) + 1

    conditions: list[str] = []
    if severity:
        conditions.append(f"c.severity = ANY(${p})")
        base_args.append([s.strip().upper() for s in severity.split(",")]); p += 1
    if kev == "true":
        conditions.append("c.is_kev = TRUE")
    if min_epss is not None:
        conditions.append(f"c.epss_score >= ${p}"); base_args.append(min_epss); p += 1
    if max_epss is not None:
        conditions.append(f"c.epss_score <= ${p}"); base_args.append(max_epss); p += 1
    if min_priority is not None and has_product:
        conditions.append(f"f.priority_score >= ${p}"); base_args.append(min_priority); p += 1
    if year is not None:
        conditions.append(f"EXTRACT(YEAR FROM c.published_at) = ${p}"); base_args.append(year); p += 1
    if keyword:
        conditions.append(
            f"(c.cve_id ILIKE ${p} OR c.raw_payload->'descriptions'->0->>'value' ILIKE ${p+1})"
        )
        base_args.append(f"%{keyword}%")
        base_args.append(f"%{keyword}%")
        p += 2

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    priority_expr = "f.priority_score" if has_product else "NULL::numeric"
    order_expr = (
        f"{priority_expr} {sort_dir} NULLS LAST"
        if sort_col == "priority_score"
        else f"c.{sort_col} {sort_dir} NULLS LAST"
    )
    extra_cols = ", f.match_confidence, f.status AS finding_status, f.assigned_to, f.priority_score" if has_product else ""

    data_sql = f"""
        SELECT c.cve_id, c.source, c.severity, c.cvss_v3_score, c.cvss_v2_score,
               c.epss_score, c.epss_percentile, c.is_kev,
               c.kev_added_date, c.published_at, c.last_modified_at,
               c.raw_payload->'descriptions'->0->>'value' AS description
               {extra_cols}
        FROM cves c {join} {where}
        ORDER BY {order_expr}
        LIMIT ${p} OFFSET ${p+1}
    """
    count_sql = f"SELECT COUNT(DISTINCT c.cve_id) FROM cves c {join} {where}"

    async with pool.acquire() as conn:
        rows = await conn.fetch(data_sql, *base_args, limit, offset)
        count_row = await conn.fetchrow(count_sql, *base_args)

    total = int(count_row[0]) if count_row else 0
    return {
        "data": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
    }


@router.get("/{cve_id}")
async def cve_detail(
    cve_id: str,
    pool: asyncpg.Pool = Depends(_get_pool),
) -> dict:
    cve_id = cve_id.upper()
    if not _CVE_ID_RE.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    row = await pool.fetchrow(
        "SELECT *, raw_payload->'descriptions'->0->>'value' AS description FROM cves WHERE cve_id = $1",
        cve_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")

    affected = await pool.fetch(
        """
        SELECT p.id, p.name, p.version, p.vendor,
               f.status AS finding_status, f.match_confidence, f.priority_score
        FROM products p JOIN findings f ON f.product_id = p.id
        WHERE f.cve_id = $1
        """,
        cve_id,
    )
    result = _row_to_dict(row)
    result["affected_products"] = [dict(r) for r in affected]
    result["source"] = "db"
    return result
