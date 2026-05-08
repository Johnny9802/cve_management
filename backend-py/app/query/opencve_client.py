"""Tier 3 — OpenCVE API polling (no webhook).

Polls OpenCVE for new CVEs by vendor/product subscriptions.
Runs as a background APScheduler job (not in the hot query path).

Subscriptions are stored in the subscriptions_opencve table.
Each poll queries OpenCVE for CVEs modified since the last sync.

OpSec: only normalized CPE vendor:product strings are sent to OpenCVE.
Auth:  Bearer token via OPENCVE_API_KEY env var (optional — skip if absent).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import asyncpg
import httpx
import structlog

from app.core.config import Settings
from app.core.http import OpsecAwareClient
from app.ingestion.rate_governor import TokenBucket

logger = structlog.get_logger(__name__)

_PAGE_SIZE = 20
_MAX_PAGES = 50

_SUBS_SQL = "SELECT id, vendor, product FROM subscriptions_opencve WHERE active = TRUE"

_UPSERT_CVE_SQL = """
    INSERT INTO cves (
        cve_id, source, raw_payload, cvss_v3_score, cvss_v2_score,
        severity, published_at, last_modified_at
    )
    VALUES ($1, 'nvd_api', $2::jsonb, $3, $4, $5, $6, $7)
    ON CONFLICT (cve_id) DO NOTHING
"""

_UPDATE_SUB_SQL = """
    UPDATE subscriptions_opencve
    SET project_id = $1
    WHERE id = $2
"""


def _parse_dt(s: str | None) -> datetime:
    if not s:
        return datetime.now(tz=UTC)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
    except ValueError:
        return datetime.now(tz=UTC)


@dataclass
class OpenCveClient:
    settings: Settings
    governor: TokenBucket
    _client: OpsecAwareClient = field(init=False)

    def __post_init__(self) -> None:
        headers: dict[str, str] = {"User-Agent": "cve-management/0.1 (internal)"}
        if self.settings.opencve_api_key:
            headers["Authorization"] = f"Bearer {self.settings.opencve_api_key}"

        self._client = OpsecAwareClient(
            provider="opencve",
            enforcement=self.settings.opencve_api_key and self.settings.opsec_enforcement,
            base_url=self.settings.opencve_base_url,
            headers=headers,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def is_configured(self) -> bool:
        return bool(self.settings.opencve_api_key)

    async def poll_subscriptions(self, pool: asyncpg.Pool) -> int:
        """Poll OpenCVE for each active subscription. Returns total new CVEs inserted."""
        if not self.is_configured:
            logger.debug("opencve.poll.skipped", reason="no_api_key")
            return 0

        async with pool.acquire() as conn:
            subs = await conn.fetch(_SUBS_SQL)

        if not subs:
            logger.debug("opencve.poll.no_subscriptions")
            return 0

        total = 0
        for sub in subs:
            count = await self._poll_one(pool, sub["id"], sub["vendor"], sub["product"])
            total += count

        logger.info("opencve.poll.done", total_new=total, subscriptions=len(subs))
        return total

    async def ensure_subscription(
        self, pool: asyncpg.Pool, vendor: str, product: str
    ) -> None:
        """Register a vendor/product subscription (idempotent)."""
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO subscriptions_opencve (vendor, product)
                VALUES ($1, $2)
                ON CONFLICT (vendor, product) DO NOTHING
                """,
                vendor,
                product,
            )

    async def _poll_one(
        self, pool: asyncpg.Pool, sub_id: int, vendor: str, product: str
    ) -> int:
        """Fetch CVEs for a single vendor:product from OpenCVE and insert new ones."""
        inserted = 0
        page = 1

        while page <= _MAX_PAGES:
            await self.governor.acquire()
            try:
                resp = await self._client.get(
                    "/cve",
                    params={"vendor": vendor, "product": product, "page": page},
                )
            except httpx.RequestError as exc:
                logger.error("opencve.request_error", vendor=vendor, product=product, error=str(exc))
                break

            if resp.status_code in (401, 403):
                logger.warning("opencve.auth_error", status=resp.status_code)
                break
            if resp.status_code == 404:
                break
            if resp.status_code == 429:
                logger.warning("opencve.rate_limited")
                break
            resp.raise_for_status()

            body = resp.json()
            results = body.get("results") or body if isinstance(body, list) else []

            if not results:
                break

            rows = self._parse_cves(results)
            if rows:
                async with pool.acquire() as conn:
                    await conn.executemany(_UPSERT_CVE_SQL, rows)
                inserted += len(rows)

            # OpenCVE pagination: check for next page
            if not body.get("next") if isinstance(body, dict) else False:
                break
            if len(results) < _PAGE_SIZE:
                break
            page += 1

        if inserted:
            logger.info("opencve.poll_one.done", vendor=vendor, product=product, inserted=inserted)
        return inserted

    def _parse_cves(self, results: list[dict]) -> list[tuple]:
        rows: list[tuple] = []
        for item in results:
            cve_id = item.get("cve_id") or item.get("id")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            cvss = item.get("cvss", {})
            v3_score = None
            v2_score = None
            severity = None
            if isinstance(cvss, dict):
                v3_score = cvss.get("v3") or cvss.get("v31")
                v2_score = cvss.get("v2")
                severity = cvss.get("v3_vector", "")
            elif isinstance(cvss, (int, float)):
                v2_score = float(cvss)

            try:
                v3_score = float(v3_score) if v3_score is not None else None
                v2_score = float(v2_score) if v2_score is not None else None
            except (TypeError, ValueError):
                v3_score = v2_score = None

            published = _parse_dt(item.get("created_at") or item.get("published"))
            modified = _parse_dt(item.get("updated_at") or item.get("modified") or item.get("created_at"))

            rows.append((
                cve_id,
                json.dumps(item),
                v3_score,
                v2_score,
                severity or None,
                published,
                modified,
            ))
        return rows
