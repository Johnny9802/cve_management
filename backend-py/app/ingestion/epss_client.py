"""EPSS (Exploit Prediction Scoring System) client — FIRST.org API.

Endpoint: GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...
  - Up to 100 CVE IDs per request (API limit)
  - No authentication required
  - Cache results in Redis for 24 h (EPSS scores update daily)

Response shape:
  {"status": "OK", "data": [{"cve": "CVE-...", "epss": "0.97", "percentile": "0.99", "date": "..."}]}
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import NamedTuple

import httpx
import structlog
from redis.asyncio import Redis

from app.core.config import Settings
from app.core.http import OpsecAwareClient
from app.ingestion.rate_governor import TokenBucket

logger = structlog.get_logger(__name__)

_BATCH = 100       # EPSS hard limit per request
_TTL = 86400       # 24 h in seconds


class EpssScore(NamedTuple):
    cve_id: str
    score: float
    percentile: float


@dataclass
class EpssClient:
    settings: Settings
    governor: TokenBucket
    _client: OpsecAwareClient = field(init=False)

    def __post_init__(self) -> None:
        self._client = OpsecAwareClient(
            provider="epss",
            enforcement=self.settings.opsec_enforcement,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0),
            headers={"User-Agent": "cve-management/0.1 (internal)"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch_scores(
        self,
        cve_ids: list[str],
        redis: Redis,
    ) -> dict[str, EpssScore]:
        """Return EPSS scores for the given CVE IDs.

        Checks Redis cache first; only fetches uncached IDs from the API.
        """
        if not cve_ids:
            return {}

        results: dict[str, EpssScore] = {}
        uncached: list[str] = []

        # Bulk cache check via MGET
        cache_keys = [f"epss:{cid}" for cid in cve_ids]
        cached_values = await redis.mget(*cache_keys)
        for cve_id, cached in zip(cve_ids, cached_values, strict=False):
            if cached:
                try:
                    d = json.loads(cached)
                    results[cve_id] = EpssScore(
                        cve_id=cve_id,
                        score=float(d["epss"]),
                        percentile=float(d["percentile"]),
                    )
                except (json.JSONDecodeError, KeyError):
                    uncached.append(cve_id)
            else:
                uncached.append(cve_id)

        if uncached:
            fetched = await self._fetch_from_api(uncached)
            results.update(fetched)
            await self._cache_scores(redis, fetched)

        return results

    async def _fetch_from_api(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """Fetch scores in batches of 100."""
        results: dict[str, EpssScore] = {}

        for i in range(0, len(cve_ids), _BATCH):
            batch = cve_ids[i : i + _BATCH]
            await self.governor.acquire()

            try:
                resp = await self._client.get(
                    self.settings.epss_base_url,
                    params={"cve": ",".join(batch)},
                )
                resp.raise_for_status()
            except httpx.RequestError as exc:
                logger.error("epss.request_error", error=str(exc))
                raise

            body = resp.json()
            for entry in body.get("data", []):
                try:
                    cve_id = entry["cve"]
                    results[cve_id] = EpssScore(
                        cve_id=cve_id,
                        score=float(entry["epss"]),
                        percentile=float(entry["percentile"]),
                    )
                except (KeyError, ValueError) as exc:
                    logger.warning("epss.parse_error", entry=entry, error=str(exc))

            logger.debug("epss.batch_fetched", batch_size=len(batch), returned=len(results))

        return results

    async def _cache_scores(self, redis: Redis, scores: dict[str, EpssScore]) -> None:
        if not scores:
            return
        async with redis.pipeline(transaction=False) as pipe:
            for score in scores.values():
                pipe.setex(
                    f"epss:{score.cve_id}",
                    _TTL,
                    json.dumps({"epss": score.score, "percentile": score.percentile}),
                )
            await pipe.execute()
