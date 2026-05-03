import structlog
from redis.asyncio import Redis, ConnectionPool

logger = structlog.get_logger(__name__)


async def create_redis(url: str) -> Redis:
    pool = ConnectionPool.from_url(url, max_connections=10, decode_responses=True)
    client: Redis = Redis(connection_pool=pool)
    await client.ping()
    logger.info("cache.connected")
    return client


async def get_cached(redis: Redis, key: str) -> str | None:
    try:
        return await redis.get(key)
    except Exception as exc:
        logger.warning("cache.get_error", key=key, error=str(exc))
        return None


async def set_cached(redis: Redis, key: str, value: str, ttl_seconds: int) -> None:
    try:
        await redis.setex(key, ttl_seconds, value)
    except Exception as exc:
        logger.warning("cache.set_error", key=key, error=str(exc))


async def set_with_stale(
    redis: Redis,
    key: str,
    value: str,
    fresh_ttl: int,
    stale_ttl: int = 86400,
) -> None:
    """Store fresh entry + a long-lived stale copy for circuit-breaker fallback."""
    try:
        async with redis.pipeline(transaction=True) as pipe:
            pipe.setex(key, fresh_ttl, value)
            pipe.setex(f"{key}:stale", stale_ttl, value)
            await pipe.execute()
    except Exception as exc:
        logger.warning("cache.set_stale_error", key=key, error=str(exc))


async def get_stale(redis: Redis, key: str) -> str | None:
    try:
        return await redis.get(f"{key}:stale")
    except Exception as exc:
        logger.warning("cache.get_stale_error", key=key, error=str(exc))
        return None


async def delete_pattern(redis: Redis, pattern: str) -> int:
    count = 0
    try:
        async for key in redis.scan_iter(pattern, count=100):
            await redis.delete(key)
            count += 1
    except Exception as exc:
        logger.warning("cache.delete_pattern_error", pattern=pattern, error=str(exc))
    return count
