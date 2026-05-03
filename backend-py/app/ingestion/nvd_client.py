"""NIST NVD API v2 client — secondary ingestion source / fallback.

Used when VulnCheck is unavailable (circuit open or key missing).
NOT called in the runtime query path — ingestion background only.

Rate limits (enforced via TokenBucket in rate_governor):
  Without apiKey : 5 req / 30 s  (sleep 6 s between requests recommended)
  With apiKey    : 50 req / 30 s (sleep 6 s still recommended)

Date window constraint: lastModStartDate / lastModEndDate max 120 days.
This client chunks automatically at _CHUNK_DAYS (119) to stay within the limit.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

import httpx
import structlog

from app.core.config import Settings
from app.core.http import OpsecAwareClient
from app.ingestion.rate_governor import TokenBucket
from app.models.nvd import NvdCveRecord

logger = structlog.get_logger(__name__)

_RESULTS_PER_PAGE = 2000   # NVD v2 maximum
_CHUNK_DAYS = 119          # hard limit: 120 days max, use 119 for safety
_MAX_PAGES = 1000          # absolute pagination safety cap
def _fmt_date(dt: datetime) -> str:
    """Format datetime for NVD API v2.

    NVD accepts ISO 8601 without timezone: 2024-01-01T00:00:00.000
    The 'UTC+00:00' suffix causes 404 responses in practice.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


@dataclass
class NvdClient:
    settings: Settings
    governor: TokenBucket
    _client: OpsecAwareClient = field(init=False)

    def __post_init__(self) -> None:
        headers: dict[str, str] = {
            "User-Agent": "cve-management/0.1 (internal)",
        }
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        # OpSec wrapper: NVD only ever receives query-string params (no body),
        # so the wrapper here is mostly defensive — but the metric counter
        # makes egress accidents observable.
        self._client = OpsecAwareClient(
            provider="nvd",
            enforcement=self.settings.opsec_enforcement,
            headers=headers,
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def iter_delta(
        self,
        last_mod_date: datetime | None,
    ) -> AsyncGenerator[NvdCveRecord, None]:
        """Yield CVEs from NVD.

        Initial load (last_mod_date=None): uses pubStartDate/pubEndDate so we
        get all published CVEs regardless of their lastModified timestamp.
        NVD often back-dates lastModified when migrating records, making
        lastModStartDate return 0 results for historical ranges.

        Delta sync (last_mod_date set): uses lastModStartDate/lastModEndDate
        to pick up only CVEs modified since the last checkpoint.
        """
        now = datetime.now(tz=timezone.utc)
        is_initial = last_mod_date is None
        # Initial load: current year only — older CVEs fetched live on demand
        start = last_mod_date or datetime(now.year, 1, 1, tzinfo=timezone.utc)

        current = start
        while current < now:
            end = min(current + timedelta(days=_CHUNK_DAYS), now)
            logger.debug(
                "nvd.delta_chunk",
                mode="pub" if is_initial else "lastmod",
                start=current.isoformat(),
                end=end.isoformat(),
            )
            async for record in self._iter_pages(current, end, use_pub_date=is_initial):
                yield record
            current = end

    async def _iter_pages(
        self,
        start: datetime,
        end: datetime,
        use_pub_date: bool = False,
    ) -> AsyncGenerator[NvdCveRecord, None]:
        """Paginate a single date window via startIndex / resultsPerPage.

        use_pub_date=True  → pubStartDate/pubEndDate    (initial load)
        use_pub_date=False → lastModStartDate/lastModEndDate (delta sync)
        """
        start_index = 0
        page_num = 0

        while page_num < _MAX_PAGES:
            await self.governor.acquire()

            if use_pub_date:
                params = {
                    "pubStartDate": _fmt_date(start),
                    "pubEndDate": _fmt_date(end),
                    "startIndex": start_index,
                    "resultsPerPage": _RESULTS_PER_PAGE,
                }
            else:
                params = {
                    "lastModStartDate": _fmt_date(start),
                    "lastModEndDate": _fmt_date(end),
                    "startIndex": start_index,
                    "resultsPerPage": _RESULTS_PER_PAGE,
                }

            try:
                resp = await self._client.get(
                    self.settings.nvd_base_url, params=params
                )
            except httpx.RequestError as exc:
                logger.error("nvd.request_error", error=str(exc))
                raise

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "30"))
                logger.warning("nvd.rate_limited", retry_after=retry_after)
                await asyncio.sleep(retry_after)
                continue  # retry same page

            if resp.status_code == 404:
                # NVD returns 404 for date ranges with no data (very old ranges)
                logger.debug("nvd.range_empty", start=start.isoformat(), end=end.isoformat())
                break

            resp.raise_for_status()
            body = resp.json()

            total_results: int = body.get("totalResults", 0)
            vulns: list = body.get("vulnerabilities", [])

            logger.debug(
                "nvd.page_fetched",
                start_index=start_index,
                total=total_results,
                returned=len(vulns),
            )

            for vuln in vulns:
                try:
                    yield NvdCveRecord.from_nvd_cve(vuln)
                except (KeyError, ValueError) as exc:
                    cve_id = vuln.get("cve", {}).get("id", "unknown")
                    logger.warning("nvd.parse_error", cve_id=cve_id, error=str(exc))

            start_index += len(vulns)
            page_num += 1

            if start_index >= total_results or not vulns:
                break

            # Enforce the recommended inter-request delay (rate limit courtesy)
            await asyncio.sleep(self.settings.nvd_request_delay)
