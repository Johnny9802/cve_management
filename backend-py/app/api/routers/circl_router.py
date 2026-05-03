"""CIRCL Vulnerability-Lookup routes — /api/circl

Exposes CIRCL search to the Live Search frontend panel.
OpSec gate: caller must supply vendor+product explicitly — no asset data forwarded.

GET /api/circl                     — search CVEs by vendor + product
GET /api/circl/products            — list products for a vendor (autocomplete)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import structlog
from fastapi import APIRouter, Query, Request
from redis.asyncio import Redis

from app.models.priority import compute_priority_score

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/circl", tags=["circl"])

_BASE = "https://vulnerability.circl.lu"
_CACHE_TTL = 3600   # 1 h


def _get_redis(request: Request) -> Redis:
    return request.app.state.redis


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except ValueError:
        return None


def _severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def _normalise_item(item: dict) -> dict:
    cvss = item.get("cvss") or item.get("cvss3")
    try:
        cvss_float = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss_float = None
    sev = _severity_from_cvss(cvss_float)
    pub = _parse_dt(item.get("Published"))
    priority = compute_priority_score(
        cvss_score=cvss_float,
        severity=sev,
        epss_score=None,
        is_kev=False,
        published_at=pub,
    )
    return {
        "cve_id":        item.get("id", ""),
        "description":   item.get("summary", ""),
        "severity":      sev,
        "cvss_v3_score": None,
        "cvss_v2_score": cvss_float,
        "epss_score":    None,
        "in_cisa_kev":   False,
        "priority_score": priority,
        "published_at":  pub.isoformat() if pub else None,
    }


async def _fetch_all_pages(vendor: str, product: str) -> list[dict]:
    items: list[dict] = []
    async with httpx.AsyncClient(
        base_url=_BASE,
        timeout=httpx.Timeout(30.0),
        headers={"User-Agent": "cve-management/0.1 (internal)"},
    ) as client:
        page = 1
        while page <= 20:
            resp = await client.get(f"/api/search/{vendor}/{product}", params={"page": page})
            if resp.status_code in (404, 429):
                break
            if not resp.is_success:
                break
            batch = resp.json()
            if not isinstance(batch, list) or not batch:
                break
            items.extend(batch)
            if len(batch) < 10:
                break
            page += 1
    return items


@router.get("")
async def circl_search(
    request: Request,
    vendor: str = Query(..., min_length=1),
    product: str = Query(..., min_length=1),
    severity: str | None = None,
    year: int | None = None,
    page: int = 1,
    limit: int = 20,
) -> dict:
    redis = _get_redis(request)
    cache_key = f"circl:{vendor.lower()}:{product.lower()}"
    limit = min(100, max(1, limit))
    page = max(1, page)

    # Try cache first (full result set for this vendor:product)
    raw_cached = await redis.get(cache_key)
    if raw_cached:
        all_items = json.loads(raw_cached)
        cached = True
    else:
        try:
            all_items = await _fetch_all_pages(vendor.lower(), product.lower())
        except Exception as exc:
            logger.error("circl_search.error", error=str(exc))
            all_items = []
        await redis.setex(cache_key, _CACHE_TTL, json.dumps(all_items))
        cached = False

    normalised = [_normalise_item(i) for i in all_items if i.get("id")]

    # Apply in-memory filters (CIRCL data is fully downloaded then filtered)
    if severity:
        normalised = [i for i in normalised if (i["severity"] or "").upper() == severity.upper()]
    if year:
        normalised = [
            i for i in normalised
            if i["published_at"] and str(year) in (i["published_at"] or "")
        ]

    total = len(normalised)
    start = (page - 1) * limit
    page_data = normalised[start: start + limit]

    return {
        "data":   page_data,
        "total":  total,
        "page":   page,
        "pages":  max(1, (total + limit - 1) // limit),
        "source": "CIRCL",
        "cached": cached,
    }


@router.get("/products")
async def circl_products(
    request: Request,
    vendor: str = Query(..., min_length=2),
) -> list[str]:
    """Return known product names for a vendor from CIRCL (for autocomplete)."""
    redis = _get_redis(request)
    cache_key = f"circl:products:{vendor.lower()}"
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        async with httpx.AsyncClient(
            base_url=_BASE,
            timeout=httpx.Timeout(10.0),
            headers={"User-Agent": "cve-management/0.1 (internal)"},
        ) as client:
            resp = await client.get(f"/api/browse/{vendor.lower()}")
            if resp.is_success:
                data = resp.json()
                products = sorted(set(data)) if isinstance(data, list) else []
            else:
                products = []
    except Exception:
        products = []

    await redis.setex(cache_key, _CACHE_TTL, json.dumps(products))
    return products
