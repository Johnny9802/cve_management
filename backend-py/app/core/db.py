from contextlib import asynccontextmanager
from typing import AsyncGenerator

import asyncpg
import structlog

logger = structlog.get_logger(__name__)


async def create_pool(dsn: str) -> asyncpg.Pool:
    pool = await asyncpg.create_pool(
        dsn,
        min_size=2,
        max_size=10,
        command_timeout=60,
        server_settings={"search_path": "public"},
        statement_cache_size=0,  # safe for pgbouncer / connection poolers
    )
    logger.info("db.pool_created", min_size=2, max_size=10)
    return pool  # type: ignore[return-value]


@asynccontextmanager
async def acquire(pool: asyncpg.Pool) -> AsyncGenerator[asyncpg.Connection, None]:
    async with pool.acquire() as conn:
        yield conn  # type: ignore[misc]


@asynccontextmanager
async def transaction(pool: asyncpg.Pool) -> AsyncGenerator[asyncpg.Connection, None]:
    """Context manager that wraps a connection in an explicit transaction."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            yield conn  # type: ignore[misc]
