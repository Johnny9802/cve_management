"""Two-tier cache for CPE resolutions: Redis (fast) + cpe_resolutions table (persistent).

Read path:  Redis hit → return immediately
            Redis miss → DB lookup → populate Redis if found
Write path: DB upsert (conflict on input_string) → Redis set

TTL: Redis key expires after 24h (resolutions are stable; manual overrides invalidated on write).
"""
from __future__ import annotations

import json

import asyncpg
import structlog
from redis.asyncio import Redis

from app.models.product import CpeResolution

logger = structlog.get_logger(__name__)

_REDIS_TTL = 86400  # 24 h
_KEY_PREFIX = "cpe:resolution:"

_SELECT_SQL = """
    SELECT input_string, resolved_cpe, confidence, match_score, resolved_by
    FROM cpe_resolutions
    WHERE input_string = $1
"""

_UPSERT_SQL = """
    INSERT INTO cpe_resolutions (input_string, resolved_cpe, confidence, match_score, resolved_by)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (input_string) DO UPDATE SET
        resolved_cpe = EXCLUDED.resolved_cpe,
        confidence   = EXCLUDED.confidence,
        match_score  = EXCLUDED.match_score,
        resolved_by  = EXCLUDED.resolved_by,
        resolved_at  = NOW()
    RETURNING input_string
"""


def _redis_key(input_str: str) -> str:
    return f"{_KEY_PREFIX}{input_str.lower().strip()}"


def _to_json(res: CpeResolution) -> str:
    return json.dumps({
        "resolved_cpe": res.resolved_cpe,
        "confidence":   res.confidence,
        "match_score":  res.match_score,
        "resolved_by":  res.resolved_by,
    })


def _from_json(input_str: str, raw: str) -> CpeResolution:
    d = json.loads(raw)
    return CpeResolution(
        input_string=input_str,
        resolved_cpe=d["resolved_cpe"],
        confidence=d["confidence"],
        match_score=d.get("match_score"),
        resolved_by=d.get("resolved_by", "auto"),
        from_cache=True,
    )


class ResolutionCache:
    def __init__(self, pool: asyncpg.Pool, redis: Redis) -> None:
        self._pool = pool
        self._redis = redis

    async def get(self, input_str: str) -> CpeResolution | None:
        key = _redis_key(input_str)

        # 1. Redis
        try:
            cached = await self._redis.get(key)
            if cached:
                return _from_json(input_str, cached)
        except Exception as exc:
            logger.warning("resolution_cache.redis_get_error", error=str(exc))

        # 2. DB
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(_SELECT_SQL, input_str)
            if row:
                res = CpeResolution(
                    input_string=row["input_string"],
                    resolved_cpe=row["resolved_cpe"],
                    confidence=row["confidence"],
                    match_score=float(row["match_score"]) if row["match_score"] is not None else None,
                    resolved_by=row["resolved_by"],
                    from_cache=True,
                )
                await self._redis.setex(key, _REDIS_TTL, _to_json(res))
                return res
        except Exception as exc:
            logger.warning("resolution_cache.db_get_error", error=str(exc))

        return None

    async def save(self, resolution: CpeResolution) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    _UPSERT_SQL,
                    resolution.input_string,
                    resolution.resolved_cpe,
                    resolution.confidence,
                    resolution.match_score,
                    resolution.resolved_by,
                )
        except Exception as exc:
            logger.error("resolution_cache.db_save_error", error=str(exc))
            return

        try:
            key = _redis_key(resolution.input_string)
            await self._redis.setex(key, _REDIS_TTL, _to_json(resolution))
        except Exception as exc:
            logger.warning("resolution_cache.redis_save_error", error=str(exc))

    async def invalidate(self, input_str: str) -> None:
        """Remove a cached resolution (e.g. after manual correction)."""
        try:
            await self._redis.delete(_redis_key(input_str))
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM cpe_resolutions WHERE input_string = $1", input_str
                )
        except Exception as exc:
            logger.warning("resolution_cache.invalidate_error", error=str(exc))
