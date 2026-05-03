"""CISA Known Exploited Vulnerabilities (KEV) client.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - Static JSON, poll every 6 h
  - No authentication required
  - Full list cached in Redis; key = "kev:catalog"

Response shape:
  {"count": N, "vulnerabilities": [{"cveID": "CVE-...", "dateAdded": "YYYY-MM-DD", ...}]}
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date

import httpx
import structlog
from redis.asyncio import Redis

from app.core.config import Settings
from app.core.http import OpsecAwareClient
from app.ingestion.rate_governor import TokenBucket

logger = structlog.get_logger(__name__)

_CACHE_KEY = "kev:catalog"
_TTL = 6 * 3600  # 6 h


@dataclass
class KevClient:
    settings: Settings
    governor: TokenBucket
    _client: OpsecAwareClient = field(init=False)

    def __post_init__(self) -> None:
        self._client = OpsecAwareClient(
            provider="kev",
            enforcement=self.settings.opsec_enforcement,
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            headers={"User-Agent": "cve-management/0.1 (internal)"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_catalog(self, redis: Redis) -> dict[str, date]:
        """Return {cve_id: date_added} for all KEV entries.

        Served from Redis cache if fresh; fetches from CISA otherwise.
        """
        cached = await redis.get(_CACHE_KEY)
        if cached:
            try:
                raw: dict[str, str] = json.loads(cached)
                return {k: date.fromisoformat(v) for k, v in raw.items()}
            except (json.JSONDecodeError, ValueError):
                pass  # stale/corrupt cache — re-fetch

        catalog = await self._fetch()
        await self._cache(redis, catalog)
        return catalog

    async def _fetch(self) -> dict[str, date]:
        await self.governor.acquire()
        try:
            resp = await self._client.get(self.settings.cisa_kev_url)
            resp.raise_for_status()
        except httpx.RequestError as exc:
            logger.error("kev.request_error", error=str(exc))
            raise

        body = resp.json()
        catalog: dict[str, date] = {}
        for vuln in body.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            date_added = vuln.get("dateAdded")
            if cve_id and date_added:
                try:
                    catalog[cve_id] = date.fromisoformat(date_added)
                except ValueError:
                    logger.warning("kev.bad_date", cve_id=cve_id, date=date_added)

        logger.info("kev.fetched", count=len(catalog))
        return catalog

    async def _cache(self, redis: Redis, catalog: dict[str, date]) -> None:
        serialized = json.dumps({k: v.isoformat() for k, v in catalog.items()})
        await redis.setex(_CACHE_KEY, _TTL, serialized)
