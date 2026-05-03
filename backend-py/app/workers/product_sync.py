"""Product sync logic — queries local CVE mirror and applies version matching.

Architecture difference from Node.js:
  JS: fetches CVEs from NVD API on every sync (network-dependent, slow)
  Python: queries the local DB mirror (ingestion workers keep it current)

Flow:
  1. Load product record.
  2. Build a CPE search pattern from normalized_cpe (or product name slug).
  3. Find candidate CVEs in the local DB whose configurations CPE matches.
  4. For each candidate: run is_cve_affecting_product() (version range check).
  5. Upsert affected ones into findings, preserving human decisions.
  6. Compute priority_score per finding using the priority engine.
  7. Update product stats (cve_count, critical_count, sync_status).
  8. Invalidate dashboard cache.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import asyncpg
import structlog
from redis.asyncio import Redis

from app.core.cache import delete_pattern
from app.models.priority import compute_priority_score
from app.resolution.version_matcher import (
    extract_affected_cpes,
    is_cve_affecting_product,
    normalise_slug,
    parse_cpe_vendor_product,
)

logger = structlog.get_logger(__name__)

_MAX_CANDIDATES = 1000

_CANDIDATES_SQL = """
    SELECT DISTINCT c.cve_id, c.raw_payload, c.cvss_v3_score, c.cvss_v2_score,
           c.severity, c.epss_score, c.is_kev, c.published_at
    FROM cves c
    WHERE EXISTS (
        SELECT 1
        FROM jsonb_array_elements(c.raw_payload->'configurations') cfg,
             jsonb_array_elements(cfg->'nodes') nd,
             jsonb_array_elements(nd->'cpeMatch') m
        WHERE m->>'criteria' ILIKE $1
    )
    ORDER BY c.cvss_v3_score DESC NULLS LAST
    LIMIT $2
"""

_FINDING_UPSERT_SQL = """
    INSERT INTO findings (product_id, cve_id, status, match_confidence, match_reason, priority_score)
    VALUES ($1, $2, 'open', $3, $4, $5)
    ON CONFLICT (product_id, cve_id) DO UPDATE SET
        match_confidence = EXCLUDED.match_confidence,
        match_reason     = EXCLUDED.match_reason,
        priority_score   = EXCLUDED.priority_score,
        updated_at       = NOW()
    WHERE findings.status NOT IN ('false_positive', 'accepted_risk', 'closed')
"""

_STATS_UPDATE_SQL = """
    UPDATE products SET
        sync_status    = 'synced',
        last_synced_at = NOW(),
        updated_at     = NOW(),
        cve_count      = (
            SELECT COUNT(*) FROM findings
            WHERE product_id = $1
              AND status NOT IN ('closed', 'false_positive')
        ),
        critical_count = (
            SELECT COUNT(*) FROM findings f
            JOIN cves c ON c.cve_id = f.cve_id
            WHERE f.product_id = $1
              AND c.severity = 'CRITICAL'
              AND f.status NOT IN ('closed', 'false_positive')
        )
    WHERE id = $1
"""

_STATUS_UPDATE_SQL = "UPDATE products SET sync_status = $1, updated_at = NOW() WHERE id = $2"


@dataclass
class SyncResult:
    product_id: int
    candidates: int
    matched: int
    filtered: int
    duration_ms: int


def _build_search_pattern(product: dict[str, Any]) -> str:
    """Build a SQL ILIKE pattern for CPE criteria matching.

    Examples:
      normalized_cpe='cpe:2.3:a:nginx:nginx:1.18.0:...' → 'cpe:2.3:%:nginx:nginx:%'
      name='OpenSSL', vendor='OpenSSL Project'           → 'cpe:2.3:%:openssl_project:openssl:%'
      name='nginx', vendor=None                          → 'cpe:2.3:%:%:nginx:%'
    """
    cpe = product.get("normalized_cpe") or ""
    if cpe:
        vp = parse_cpe_vendor_product(cpe)
        if vp:
            vendor, prod = vp.split(":")
            return f"cpe:2.3:%:{vendor}:{prod}:%"

    slug = normalise_slug(product.get("name") or "")
    v_slug = normalise_slug(product.get("vendor") or "")
    if v_slug:
        return f"cpe:2.3:%:{v_slug}:{slug}:%"
    return f"cpe:2.3:%:%:{slug}:%"


async def sync_product(
    pool: asyncpg.Pool,
    redis: Redis,
    product_id: int,
) -> SyncResult:
    t0 = time.monotonic()

    # 1. Load product
    product_row = await pool.fetchrow("SELECT * FROM products WHERE id = $1", product_id)
    if not product_row:
        raise ValueError(f"Product {product_id} not found")

    product = dict(product_row)
    log = logger.bind(
        product_id=product_id,
        name=product["name"],
        version=product["version"],
    )

    await pool.execute(_STATUS_UPDATE_SQL, "syncing", product_id)

    # 2. Find candidate CVEs
    pattern = _build_search_pattern(product)
    log.info("product_sync.start", pattern=pattern)

    candidates = await pool.fetch(_CANDIDATES_SQL, pattern, _MAX_CANDIDATES)
    if not candidates:
        await pool.execute(_STATUS_UPDATE_SQL, "synced", product_id)
        log.info("product_sync.no_candidates")
        return SyncResult(
            product_id=product_id,
            candidates=0, matched=0, filtered=0,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    # 3. Version matching + finding upsert
    matched = 0
    filtered = 0
    finding_rows: list[tuple] = []

    for row in candidates:
        raw = row["raw_payload"]
        if isinstance(raw, str):
            raw = json.loads(raw)

        affected_cpes = extract_affected_cpes(raw)
        result = is_cve_affecting_product(product, affected_cpes)

        if not result.affected:
            filtered += 1
            log.debug(
                "product_sync.filtered",
                cve_id=row["cve_id"],
                reason=result.reason,
            )
            continue

        priority = compute_priority_score(
            cvss_score=float(row["cvss_v3_score"]) if row["cvss_v3_score"] is not None else None,
            severity=row["severity"],
            epss_score=float(row["epss_score"]) if row["epss_score"] is not None else None,
            is_kev=bool(row["is_kev"]),
            published_at=row["published_at"],
        )

        finding_rows.append((
            product_id,
            row["cve_id"],
            result.confidence.value,
            result.reason[:500],
            priority,
        ))
        matched += 1

    if finding_rows:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(_FINDING_UPSERT_SQL, finding_rows)
                await conn.execute(_STATS_UPDATE_SQL, product_id)
    else:
        await pool.execute(_STATUS_UPDATE_SQL, "synced", product_id)

    # 4. Invalidate caches
    await delete_pattern(redis, "dashboard:*")
    await delete_pattern(redis, f"cves:product:{product_id}*")

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    log.info(
        "product_sync.complete",
        candidates=len(candidates),
        matched=matched,
        filtered=filtered,
        duration_ms=elapsed_ms,
    )
    return SyncResult(
        product_id=product_id,
        candidates=len(candidates),
        matched=matched,
        filtered=filtered,
        duration_ms=elapsed_ms,
    )
