"""Live NVD search — /api/live

Queries NVD API in real-time for keyword / CPE / CVE-ID searches.
Used by the "Cerca NVD Live" tab in the frontend.

OpSec: receives search terms from the user, NOT asset inventory.
No product/hostname/IP data is ever forwarded to NVD.

NVD API constraint: keywordSearch CANNOT be combined with date params.
Date filters (from_/to) only work for CPE and ID searches.

Pagination strategy for keyword searches:
  NVD returns results oldest-first with no sort parameter.
  To show recent CVEs first, we fetch page 1 to get totalResults,
  then re-fetch using startIndex = totalResults - limit to get the
  most recent page. This costs 2 NVD calls on the first search,
  subsequent pages go forward from the newest.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from redis.asyncio import Redis

from app.core.config import get_settings
from app.models.nvd import NvdCveRecord
from app.models.priority import compute_priority_score

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/live", tags=["live-search"])

_CACHE_TTL = 120   # 2 min
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _get_redis(request: Request) -> Redis:
    return request.app.state.redis


def _fmt(dt_str: str) -> str:
    try:
        d = datetime.fromisoformat(dt_str)
        return d.strftime("%Y-%m-%dT%H:%M:%S.000")
    except ValueError:
        return dt_str


def _enrich(record: NvdCveRecord) -> dict[str, Any]:
    priority = compute_priority_score(
        cvss_score=record.cvss_v3_score,
        severity=record.severity,
        epss_score=None,
        is_kev=False,
        published_at=record.published_at,
    )
    desc = ""
    for d in (record.raw_payload.get("descriptions") or []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc:
        descs = record.raw_payload.get("descriptions") or []
        desc = descs[0].get("value", "") if descs else ""

    return {
        "cve_id":          record.cve_id,
        "description":     desc,
        "severity":        record.severity,
        "cvss_v3_score":   record.cvss_v3_score,
        "cvss_v2_score":   record.cvss_v2_score,
        "epss_score":      None,
        "in_cisa_kev":     False,
        "priority_score":  priority,
        "published_at":    record.published_at.isoformat() if record.published_at else None,
        "last_modified_at": record.last_modified_at.isoformat() if record.last_modified_at else None,
    }


async def _nvd_fetch(
    params: dict,
    headers: dict,
) -> dict:
    """Single NVD API call. Returns the parsed JSON body."""
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        resp = await client.get(_NVD_BASE, params=params, headers=headers)
    if resp.status_code == 429:
        raise HTTPException(status_code=429, detail="NVD rate limit — riprova tra qualche secondo")
    if resp.status_code == 404:
        return {"totalResults": 0, "vulnerabilities": []}
    resp.raise_for_status()
    return resp.json()


@router.get("")
async def live_search(
    request: Request,
    redis: Redis = Depends(_get_redis),
    q: str | None = None,
    cpe: str | None = None,
    id: str | None = None,
    severity: str | None = None,
    from_: str | None = None,
    to: str | None = None,
    page: int = 1,
    limit: int = 20,
) -> dict:
    settings = get_settings()
    limit = min(100, max(1, limit))
    page = max(1, page)

    if not any([q, cpe, id]):
        raise HTTPException(status_code=400, detail="Specify at least one of: q, cpe, id")

    headers: dict[str, str] = {"User-Agent": "cve-management/0.1 (internal)"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    # Base NVD params (no pagination yet)
    base_params: dict[str, Any] = {}
    if q:
        base_params["keywordSearch"] = q
    if cpe:
        base_params["cpeName"] = cpe
    if id:
        base_params["cveId"] = id.upper()

    # NVD restriction: keywordSearch cannot be combined with date params
    if not q:
        if from_:
            base_params["pubStartDate"] = _fmt(from_)
        if to:
            base_params["pubEndDate"] = _fmt(to)

    cache_key = f"live:{json.dumps(base_params, sort_keys=True)}:p{page}:l{limit}"
    cached = await redis.get(cache_key)
    if cached:
        result = json.loads(cached)
        result["cached"] = True
        return result

    try:
        if q and page == 1:
            # Keyword search page 1: fetch the MOST RECENT results.
            # NVD returns oldest-first, so we need to jump to the last page.
            # Step 1: get total count with 1 result to minimise data transfer.
            probe = await _nvd_fetch(
                {**base_params, "resultsPerPage": 1, "startIndex": 0}, headers
            )
            total = probe.get("totalResults", 0)
            if total == 0:
                return {
                    "data": [], "total": 0, "page": 1, "pages": 0,
                    "source": "NVD", "cached": False, "chunked": False, "chunks_fetched": 0,
                }
            # Step 2: jump to last page (most recent)
            start = max(0, total - limit)
            body = await _nvd_fetch(
                {**base_params, "resultsPerPage": limit, "startIndex": start}, headers
            )
        else:
            # Normal forward pagination for non-keyword or subsequent pages
            # page 1 = most recent (start = total - limit), page 2 = one step back, etc.
            if q:
                # Need total to calculate reverse offset
                probe = await _nvd_fetch(
                    {**base_params, "resultsPerPage": 1, "startIndex": 0}, headers
                )
                total = probe.get("totalResults", 0)
                start = max(0, total - page * limit)
                body = await _nvd_fetch(
                    {**base_params, "resultsPerPage": limit, "startIndex": start}, headers
                )
            else:
                body = await _nvd_fetch(
                    {**base_params, "resultsPerPage": limit, "startIndex": (page - 1) * limit},
                    headers,
                )

    except HTTPException:
        raise
    except httpx.RequestError as exc:
        logger.error("live_search.request_error", error=str(exc))
        raise HTTPException(status_code=502, detail="NVD non raggiungibile — riprova")

    total = body.get("totalResults", 0)
    vulns = body.get("vulnerabilities", [])

    data = []
    for vuln in vulns:
        try:
            record = NvdCveRecord.from_nvd_cve(vuln)
            item = _enrich(record)
            if severity and (item["severity"] or "").upper() != severity.upper():
                continue
            data.append(item)
        except Exception:
            pass

    # Sort DESC within the page (newest first)
    data.sort(key=lambda x: x.get("published_at") or "", reverse=True)

    result = {
        "data":          data,
        "total":         total,
        "page":          page,
        "pages":         max(1, (total + limit - 1) // limit),
        "source":        "NVD",
        "cached":        False,
        "chunked":       False,
        "chunks_fetched": 0,
    }

    await redis.setex(cache_key, _CACHE_TTL, json.dumps(result))
    return result
