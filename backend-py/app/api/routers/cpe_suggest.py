"""CPE autocomplete — /api/cpe-suggest

Queries NVD CPE API for product suggestions.
Used by the Live Search CPE mode autocomplete dropdown.

Query params:
  q     — keyword (min 2 chars)
  limit — max results (default 15)
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, Depends, Query, Request
from redis.asyncio import Redis

from app.core.config import get_settings

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/cpe-suggest", tags=["cpe-suggest"])

_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_CACHE_TTL = 3600  # 1h


def _get_redis(request: Request) -> Redis:
    return request.app.state.redis


@router.get("")
async def cpe_suggest(
    request: Request,
    redis: Redis = Depends(_get_redis),
    q: str = Query(..., min_length=2),
    limit: int = 15,
) -> list[dict]:
    settings = get_settings()
    limit = min(30, max(1, limit))
    cache_key = f"cpe:suggest:{q.strip().lower()}"

    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    headers: dict[str, str] = {"User-Agent": "cve-management/0.1 (internal)"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            # Fetch up to 500 to find non-deprecated entries
            all_products: list[Any] = []
            for start_index in range(0, 500, 100):
                resp = await client.get(
                    _CPE_API,
                    params={"keywordSearch": q.strip(), "resultsPerPage": 100, "startIndex": start_index},
                    headers=headers,
                )
                if not resp.is_success:
                    break
                body = resp.json()
                batch = body.get("products") or []
                all_products.extend(batch)
                total = body.get("totalResults", 0)
                if len(all_products) >= total or not batch:
                    break
                non_dep = [p for p in all_products if not (p.get("cpe") or {}).get("deprecated")]
                if len(non_dep) >= limit * 3:
                    break

        seen: dict[str, dict] = {}
        seen_dep: dict[str, dict] = {}
        for p in all_products:
            cpe_obj = p.get("cpe") or {}
            cpe_name = cpe_obj.get("cpeName") or ""
            parts = cpe_name.split(":")
            if len(parts) < 6:
                continue
            part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
            group_key = f"{vendor}:{product}"
            search_cpe = (
                f"cpe:2.3:{part}:{vendor}:{product}"
                if version in ("*", "")
                else f"cpe:2.3:{part}:{vendor}:{product}:{version}"
            )
            titles = cpe_obj.get("titles") or []
            raw_title = next(
                (t.get("title", "") for t in titles if t.get("lang") == "en"),
                (titles[0].get("title", "") if titles else product),
            )
            import re
            title = re.sub(r"\s+on\s+(x64|x86|arm64)\s*$", "", raw_title, flags=re.IGNORECASE).strip()
            entry = {"cpeName": search_cpe, "title": title, "vendor": vendor, "product": product, "part": part}
            if not cpe_obj.get("deprecated"):
                if group_key not in seen:
                    seen[group_key] = entry
            else:
                if group_key not in seen_dep:
                    seen_dep[group_key] = entry

        primary = list(seen.values())
        secondary = list(seen_dep.values())
        results = (primary if primary else secondary)[:limit]

    except Exception as exc:
        logger.warning("cpe_suggest.error", error=str(exc))
        return []

    await redis.setex(cache_key, _CACHE_TTL, json.dumps(results))
    return results
