"""Tier 2 — CIRCL Vulnerability-Lookup fallback.

Called ONLY when Tier 1 (local DB) returns no results for a product.

OpSec gate (mandatory):
  - Only normalized CPE vendor:product strings are sent to CIRCL.
  - Raw product names, hostnames, and IP addresses MUST NOT leave the perimeter.
  - If the product has no resolved CPE → skip Tier 2 silently.

Rate limit: 20 000 req/day (enforced by TokenBucket in rate_governor).
Endpoint:   GET https://vulnerability.circl.lu/api/search/{vendor}/{product}

On cache miss + CIRCL hit:
  - New CVE records are inserted into the local mirror (source='circl').
  - A finding is created so the next Tier 1 query will find it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import asyncpg
import httpx
import structlog
from redis.asyncio import Redis

from app.core.config import Settings
from app.core.http import OpsecAwareClient
from app.ingestion.rate_governor import TokenBucket
from app.resolution.version_matcher import parse_cpe_vendor_product

logger = structlog.get_logger(__name__)

_PAGE_SIZE = 10       # CIRCL default page size
_MAX_PAGES = 10       # safety cap — 100 CVEs per product per call is enough
_CACHE_TTL = 3600     # 1 h — CIRCL results are volatile, keep cache short

_UPSERT_CVE_SQL = """
    INSERT INTO cves (
        cve_id, source, raw_payload, cvss_v3_score, cvss_v2_score,
        severity, published_at, last_modified_at
    )
    VALUES ($1, 'circl', $2::jsonb, $3, $4, $5, $6, $7)
    ON CONFLICT (cve_id) DO NOTHING
"""

_UPSERT_FINDING_SQL = """
    INSERT INTO findings (product_id, cve_id, status, match_confidence, match_reason)
    VALUES ($1, $2, 'open', 'uncertain', 'circl_fallback')
    ON CONFLICT (product_id, cve_id) DO NOTHING
"""


def _circl_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_circl_dt(s: str | None) -> datetime:
    if not s:
        return datetime.now(tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(tz=timezone.utc)


@dataclass
class CirclClient:
    settings: Settings
    governor: TokenBucket
    _client: OpsecAwareClient = field(init=False)

    def __post_init__(self) -> None:
        self._client = OpsecAwareClient(
            provider="circl",
            enforcement=self.settings.opsec_enforcement,
            base_url=self.settings.circl_base_url,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0),
            headers={"User-Agent": "cve-management/0.1 (internal)"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch_and_store(
        self,
        product_id: int,
        normalized_cpe: str,
        pool: asyncpg.Pool,
        redis: Redis,
    ) -> int:
        """Fetch CVEs from CIRCL for the product's CPE and insert them locally.

        Returns the number of new CVE records inserted.
        The OpSec gate is enforced here: only vendor:product extracted from
        the normalized CPE is sent to CIRCL.
        """
        vp = parse_cpe_vendor_product(normalized_cpe)
        if not vp:
            logger.warning(
                "circl.opsec_gate.no_cpe",
                product_id=product_id,
                cpe=normalized_cpe,
            )
            return 0

        vendor, product = vp.split(":")

        # Redis cache check — avoid re-fetching within the TTL window
        cache_key = f"circl:{vendor}:{product}"
        cached_ids = await redis.get(cache_key)
        if cached_ids:
            logger.debug("circl.cache_hit", vendor=vendor, product=product)
            cve_ids: list[str] = json.loads(cached_ids)
            await self._upsert_findings_only(pool, product_id, cve_ids)
            return 0  # no new CVE records inserted (already in DB or cache-only)

        logger.info(
            "circl.fetch_start",
            vendor=vendor,
            product=product,
            product_id=product_id,
        )

        items = await self._paginate(vendor, product)
        if not items:
            return 0

        inserted = await self._store(pool, product_id, items)

        # Cache the CVE IDs for this vendor:product
        await redis.setex(
            cache_key,
            _CACHE_TTL,
            json.dumps([i.get("id") for i in items if i.get("id")]),
        )
        logger.info(
            "circl.fetch_done",
            vendor=vendor,
            product=product,
            fetched=len(items),
            inserted=inserted,
        )
        return inserted

    async def _paginate(self, vendor: str, product: str) -> list[dict]:
        items: list[dict] = []
        page = 1

        while page <= _MAX_PAGES:
            await self.governor.acquire()
            try:
                resp = await self._client.get(
                    f"/{vendor}/{product}",
                    params={"page": page},
                )
            except httpx.RequestError as exc:
                logger.error("circl.request_error", error=str(exc))
                break

            if resp.status_code == 404:
                break
            if resp.status_code == 429:
                logger.warning("circl.rate_limited", page=page)
                break
            resp.raise_for_status()

            batch = resp.json()
            if not isinstance(batch, list) or not batch:
                break

            items.extend(batch)
            if len(batch) < _PAGE_SIZE:
                break
            page += 1

        return items

    async def _store(
        self, pool: asyncpg.Pool, product_id: int, items: list[dict]
    ) -> int:
        inserted = 0
        cve_rows: list[tuple] = []
        finding_rows: list[tuple] = []

        for item in items:
            cve_id = item.get("id")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            cvss = item.get("cvss") or item.get("cvss3")
            try:
                cvss_float = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss_float = None

            published = _parse_circl_dt(item.get("Published"))
            modified = _parse_circl_dt(item.get("Modified") or item.get("Published"))

            cve_rows.append((
                cve_id,
                json.dumps(item),
                None,                           # cvss_v3_score (no v3 from CIRCL)
                cvss_float,                     # cvss_v2_score
                _circl_severity(cvss_float),
                published,
                modified,
            ))
            finding_rows.append((product_id, cve_id))

        if not cve_rows:
            return 0

        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(_UPSERT_CVE_SQL, cve_rows)
                await conn.executemany(_UPSERT_FINDING_SQL, finding_rows)
                inserted = len(cve_rows)

        return inserted

    async def _upsert_findings_only(
        self, pool: asyncpg.Pool, product_id: int, cve_ids: list[str]
    ) -> None:
        """Link already-stored CVEs to this product without re-fetching from CIRCL."""
        if not cve_ids:
            return
        rows = [(product_id, cve_id) for cve_id in cve_ids]
        async with pool.acquire() as conn:
            await conn.executemany(_UPSERT_FINDING_SQL, rows)
