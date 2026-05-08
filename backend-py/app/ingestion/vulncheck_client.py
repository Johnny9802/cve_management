"""VulnCheck NVD++ API client.

Primary source for CVE ingestion:
  - Bulk:  GET /v3/backup/nist-nvd2  → S3 pre-signed URLs → NDJSON.gz stream
  - Delta: GET /v3/index/nist-nvd2   → paginated NVD-compatible JSON

Free tier notes:
  - Bulk S3 endpoint may return 402; falls back to delta pagination automatically.
  - Rate: conservative 10 req/60s via TokenBucket (overridden by paid tier config).
  - Auth: Authorization: Token {api_key}
"""
from __future__ import annotations

import gzip
import json
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import structlog

from app.core.config import Settings
from app.core.http import OpsecAwareClient
from app.ingestion.rate_governor import TokenBucket
from app.models.nvd import NvdCveRecord

logger = structlog.get_logger(__name__)

_MAX_PAGES = 500       # hard safety cap on pagination
_BATCH_SIZE = 2000     # max items per page (NVD-compatible)
_CHUNK_DAYS = 119      # NVD hard limit: lastModStartDate/End max 120 days


@dataclass
class VulnCheckClient:
    settings: Settings
    governor: TokenBucket
    _client: OpsecAwareClient = field(init=False)

    def __post_init__(self) -> None:
        self._client = OpsecAwareClient(
            provider="vulncheck",
            enforcement=self.settings.opsec_enforcement,
            base_url=self.settings.vulncheck_base_url,
            headers={
                "Authorization": f"Token {self.settings.vulncheck_api_key}",
                "User-Agent": "cve-management/0.1 (internal)",
                "X-Request-ID": "",  # filled per-request
            },
            timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=5.0),
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    async def iter_bulk(self) -> AsyncGenerator[NvdCveRecord, None]:
        """Yield all CVEs from the S3 bulk backup.

        Falls back to full delta (no date filter) on 402/403 (free-tier restriction).
        """
        urls = await self._fetch_backup_urls()
        if urls is None:
            logger.warning("vulncheck.bulk_unavailable", reason="403/402 — falling back to delta")
            async for record in self.iter_delta(last_mod_date=None):
                yield record
            return

        logger.info("vulncheck.bulk_start", file_count=len(urls))
        total = 0
        for url in urls:
            async for record in self._stream_s3_ndjson(url):
                total += 1
                yield record
        logger.info("vulncheck.bulk_complete", total=total)

    async def iter_delta(
        self,
        last_mod_date: datetime | None,
    ) -> AsyncGenerator[NvdCveRecord, None]:
        """Yield CVEs modified since last_mod_date.

        Automatically chunks ranges > 119 days (NVD hard limit).
        If last_mod_date is None, yields all CVEs (full initial load via API).
        """
        now = datetime.now(tz=UTC)

        if last_mod_date is None:
            # Full initial load: last 7 years (older CVEs from VulnCheck S3 bulk)
            now_vc = datetime.now(tz=UTC)
            start = datetime(now_vc.year, 1, 1, tzinfo=UTC)
        else:
            start = last_mod_date

        # Split into ≤ CHUNK_DAYS windows
        current = start
        while current < now:
            end = min(current + timedelta(days=_CHUNK_DAYS), now)
            logger.debug("vulncheck.delta_chunk", start=current.isoformat(), end=end.isoformat())
            async for record in self._iter_pages(
                last_mod_start=current,
                last_mod_end=end,
            ):
                yield record
            current = end

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    async def _fetch_backup_urls(self) -> list[str] | None:
        """Return S3 pre-signed URLs from the backup index, or None if unavailable."""
        await self.governor.acquire()
        try:
            resp = await self._client.get("/v3/backup/nist-nvd2")
        except httpx.RequestError as exc:
            logger.error("vulncheck.backup_request_error", error=str(exc))
            raise

        if resp.status_code in (402, 403):
            return None
        resp.raise_for_status()

        data = resp.json()
        return [item["url"] for item in data.get("data", []) if "url" in item]

    async def _stream_s3_ndjson(self, url: str) -> AsyncGenerator[NvdCveRecord, None]:
        """Download and stream-decompress a VulnCheck S3 NDJSON.gz file.

        No rate governor needed — S3 downloads are unlimited.
        """
        logger.debug("vulncheck.s3_download_start", url=url[:80])
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(read=300.0)) as s3:
                resp = await s3.get(url)
                resp.raise_for_status()
                compressed = resp.content
        except httpx.RequestError as exc:
            logger.error("vulncheck.s3_download_error", url=url[:80], error=str(exc))
            raise

        try:
            raw = gzip.decompress(compressed)
        except OSError:
            # Already decompressed (e.g. plain NDJSON)
            raw = compressed

        count = 0
        for line in raw.decode("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                yield NvdCveRecord.from_nvd_cve(obj)
                count += 1
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("vulncheck.parse_error", error=str(exc))
        logger.debug("vulncheck.s3_download_complete", records=count)

    async def _iter_pages(
        self,
        last_mod_start: datetime,
        last_mod_end: datetime,
    ) -> AsyncGenerator[NvdCveRecord, None]:
        """Paginate through the VulnCheck /v3/index/nist-nvd2 endpoint."""
        page = 1
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"

        while page <= _MAX_PAGES:
            await self.governor.acquire()

            params = {
                "lastModStartDate": last_mod_start.strftime(fmt),
                "lastModEndDate": last_mod_end.strftime(fmt),
                "limit": _BATCH_SIZE,
                "page": page,
            }

            try:
                resp = await self._client.get("/v3/index/nist-nvd2", params=params)
            except httpx.RequestError as exc:
                logger.error("vulncheck.request_error", page=page, error=str(exc))
                raise

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "30"))
                logger.warning("vulncheck.rate_limited", retry_after=retry_after)
                import asyncio
                await asyncio.sleep(retry_after)
                continue

            resp.raise_for_status()
            body = resp.json()

            items = body.get("data") or []
            if not items:
                break

            for item in items:
                try:
                    yield NvdCveRecord.from_nvd_cve(item)
                except (KeyError, ValueError) as exc:
                    logger.warning("vulncheck.parse_error", error=str(exc), cve_id=item.get("id"))

            meta = body.get("_meta", {})
            total_pages = meta.get("total_pages", 1)
            logger.debug(
                "vulncheck.page_fetched",
                page=page,
                total_pages=total_pages,
                items=len(items),
            )

            if page >= total_pages:
                break
            page += 1
