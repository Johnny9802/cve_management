"""Intel router — GET /api/cves/{cve_id}/intel (P3).

Aggregates CVE core data, exploitation signals, exploits links, references
and the affected products into a single payload. Supports an optional
``refresh=true`` query parameter that forces a fresh vulnx call (subject
to circuit breaker / daily-limit). Cached responses are stored in Redis
under ``intel:<CVE-ID>`` for ``settings.intel_cache_ttl_seconds``
(default 600s).

Degraded mode
-------------
If vulnx is unavailable (circuit OPEN, network error, etc.) the endpoint
still returns successfully with the data we have locally, plus
``_meta.degraded = true`` so the UI can render a "stale data" indicator.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from redis.asyncio import Redis

from app.core.cache import get_cached, set_cached
from app.core.config import Settings, get_settings
from app.ingestion.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)
from app.ingestion.vulnx_client import VulnxClient
from app.models.intel import IntelRecord
from app.models.priority import (
    compute_priority_factors,
    compute_priority_score,
    get_priority_label,
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/cves", tags=["intel"])

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_INTEL_CACHE_PREFIX = "intel:"


# ---------------------------------------------------------------- DI helpers

def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


def _get_redis(request: Request) -> Redis:
    return request.app.state.redis


def _get_vulnx(request: Request) -> VulnxClient | None:
    return getattr(request.app.state, "vulnx_client", None)


def _get_circuit(request: Request, name: str) -> CircuitBreaker | None:
    breakers: dict[str, CircuitBreaker] = getattr(
        request.app.state, "circuit_breakers", {}
    )
    return breakers.get(name)


# ---------------------------------------------------------------- route

@router.get("/{cve_id}/intel")
async def cve_intel(
    cve_id: str,
    request: Request,
    refresh: bool = False,
    pool: asyncpg.Pool = Depends(_get_pool),
    redis: Redis = Depends(_get_redis),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    cve_id = cve_id.upper()
    if not _CVE_ID_RE.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    cache_key = f"{_INTEL_CACHE_PREFIX}{cve_id}"
    if not refresh:
        cached = await get_cached(redis, cache_key)
        if cached:
            try:
                payload = json.loads(cached)
                payload["_meta"]["cache_hit"] = True
                return payload
            except (json.JSONDecodeError, KeyError):
                logger.warning("intel.cache_corrupt", cve_id=cve_id)

    cve_row = await pool.fetchrow(
        """
        SELECT cve_id, source, severity,
               cvss_v3_score, cvss_v3_vector, cvss_v2_score,
               epss_score, epss_percentile, epss_updated_at,
               is_kev, kev_added_date,
               has_public_poc, has_nuclei_template, exploitability_updated_at,
               published_at, last_modified_at,
               raw_payload->'descriptions'->0->>'value' AS description,
               raw_payload
        FROM cves
        WHERE cve_id = $1
        """,
        cve_id,
    )
    if cve_row is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")

    affected = await pool.fetch(
        """
        SELECT p.id, p.name, p.vendor, p.version,
               f.status         AS finding_status,
               f.match_confidence,
               f.priority_score
        FROM products p
        JOIN findings f ON f.product_id = p.id
        WHERE f.cve_id = $1
        ORDER BY f.priority_score DESC NULLS LAST, p.name ASC
        LIMIT 200
        """,
        cve_id,
    )

    intel_record: IntelRecord | None = None
    degraded = False
    degraded_reason: str | None = None

    vulnx = _get_vulnx(request)
    circuit = _get_circuit(request, "vulnx")
    expl_age_h = _hours_since(cve_row["exploitability_updated_at"])

    should_refresh_vulnx = bool(
        refresh and vulnx is not None and vulnx.is_configured
    )

    if should_refresh_vulnx and circuit and circuit.state == CircuitState.OPEN:
        degraded = True
        degraded_reason = "vulnx_circuit_open"
        should_refresh_vulnx = False

    if should_refresh_vulnx:
        assert vulnx is not None  # narrowed for type-checker
        try:
            if circuit:
                fetched = await circuit.call(vulnx.fetch_intel, [cve_id])
            else:
                fetched = await vulnx.fetch_intel([cve_id])
            intel_record = fetched.get(cve_id)
            if intel_record is not None:
                await pool.execute(
                    """
                    UPDATE cves
                    SET has_public_poc            = $1,
                        has_nuclei_template       = $2,
                        exploitability_updated_at = $3,
                        updated_at                = NOW()
                    WHERE cve_id = $4
                    """,
                    intel_record.has_public_poc,
                    intel_record.has_nuclei_template,
                    intel_record.fetched_at,
                    cve_id,
                )
        except CircuitOpenError as exc:
            degraded = True
            degraded_reason = f"vulnx_circuit_open:{exc}"
        except Exception as exc:
            logger.warning("intel.vulnx_refresh_failed", cve_id=cve_id, error=str(exc))
            degraded = True
            degraded_reason = "vulnx_error"

    # Use freshly-fetched intel if we have it, otherwise the DB row.
    has_poc = (
        intel_record.has_public_poc
        if intel_record is not None
        else cve_row["has_public_poc"]
    )
    has_nuclei = (
        intel_record.has_nuclei_template
        if intel_record is not None
        else cve_row["has_nuclei_template"]
    )

    cvss_for_score = cve_row["cvss_v3_score"] or cve_row["cvss_v2_score"]
    score = compute_priority_score(
        cvss_score=float(cvss_for_score) if cvss_for_score is not None else None,
        severity=cve_row["severity"],
        epss_score=float(cve_row["epss_score"]) if cve_row["epss_score"] is not None else None,
        is_kev=bool(cve_row["is_kev"]),
        published_at=cve_row["published_at"],
        has_public_poc=bool(has_poc) if has_poc is not None else False,
        has_nuclei_template=bool(has_nuclei) if has_nuclei is not None else False,
    )
    factors = compute_priority_factors(
        cvss_score=float(cvss_for_score) if cvss_for_score is not None else None,
        severity=cve_row["severity"],
        epss_score=float(cve_row["epss_score"]) if cve_row["epss_score"] is not None else None,
        is_kev=bool(cve_row["is_kev"]),
        published_at=cve_row["published_at"],
        has_public_poc=bool(has_poc) if has_poc is not None else False,
        has_nuclei_template=bool(has_nuclei) if has_nuclei is not None else False,
    )
    label = get_priority_label(score)

    cwe = _extract_cwe(cve_row["raw_payload"])
    references = _extract_references(cve_row["raw_payload"])

    payload: dict[str, Any] = {
        "cve_id": cve_id,
        "source": _source_tag(intel_record is not None, vulnx is not None),
        "core": {
            "severity": cve_row["severity"],
            "cvss_v3_score": _num(cve_row["cvss_v3_score"]),
            "cvss_v3_vector": cve_row["cvss_v3_vector"],
            "cvss_v2_score": _num(cve_row["cvss_v2_score"]),
            "description": cve_row["description"],
            "published_at": _isoformat(cve_row["published_at"]),
            "last_modified_at": _isoformat(cve_row["last_modified_at"]),
            "cwe": cwe,
        },
        "exploitation": {
            "is_kev": bool(cve_row["is_kev"]),
            "kev_added_date": _isoformat(cve_row["kev_added_date"]),
            "epss_score": _num(cve_row["epss_score"]),
            "epss_percentile": _num(cve_row["epss_percentile"]),
            "epss_updated_at": _isoformat(cve_row["epss_updated_at"]),
            "has_public_poc": _maybe_bool(has_poc),
            "has_nuclei_template": _maybe_bool(has_nuclei),
            "exploitability_updated_at": _isoformat(
                cve_row["exploitability_updated_at"]
            ),
        },
        "exploits": {
            "poc_urls": intel_record.poc_urls if intel_record else [],
            "template_paths": intel_record.template_paths if intel_record else [],
        },
        "references": references,
        "affected_products": [
            {
                "id": r["id"],
                "name": r["name"],
                "vendor": r["vendor"],
                "version": r["version"],
                "finding_status": r["finding_status"],
                "match_confidence": r["match_confidence"],
                "priority_score": _num(r["priority_score"]),
            }
            for r in affected
        ],
        "priority": {
            "score": score,
            "label": label["label"],
            "color": label["color"],
            "factors": factors,
        },
        "_meta": {
            "fetched_at": datetime.now(tz=UTC).isoformat(),
            "exploitability_age_hours": expl_age_h,
            "degraded": degraded,
            "degraded_reason": degraded_reason,
            "cache_hit": False,
        },
    }

    # Only cache fresh non-degraded responses; let the next request retry
    # vulnx if we are currently degraded.
    if not degraded:
        try:
            await set_cached(
                redis,
                cache_key,
                json.dumps(payload, default=str),
                settings.intel_cache_ttl_seconds,
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("intel.cache_set_failed", cve_id=cve_id, error=str(exc))

    return payload


# ----------------------------------------------------------------- helpers

def _num(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _isoformat(v: Any) -> str | None:
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v)


def _maybe_bool(v: Any) -> bool | None:
    if v is None:
        return None
    return bool(v)


def _hours_since(ts: Any) -> float | None:
    if ts is None:
        return None
    if not hasattr(ts, "tzinfo"):
        return None
    pub = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    delta = datetime.now(tz=UTC) - pub
    return round(delta.total_seconds() / 3600.0, 2)


def _source_tag(refreshed: bool, vulnx_available: bool) -> str:
    if refreshed:
        return "local+vulnx"
    if vulnx_available:
        return "local"
    return "local_only"


def _extract_cwe(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return []
    weaknesses = raw.get("weaknesses") or []
    out: list[str] = []
    if isinstance(weaknesses, list):
        for w in weaknesses:
            descs = (w or {}).get("description") or []
            if isinstance(descs, list):
                for d in descs:
                    if isinstance(d, dict) and isinstance(d.get("value"), str):
                        if d["value"].startswith("CWE-") and d["value"] not in out:
                            out.append(d["value"])
    return out


def _extract_references(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, dict):
        return []
    refs = raw.get("references") or []
    out: list[dict[str, str]] = []
    if isinstance(refs, list):
        for r in refs:
            if not isinstance(r, dict):
                continue
            url = r.get("url")
            if not isinstance(url, str):
                continue
            tags = r.get("tags") or []
            tag = tags[0] if isinstance(tags, list) and tags else None
            out.append({"url": url, "type": tag or "reference"})
    return out
