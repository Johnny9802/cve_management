"""Root conftest — unit test fixtures only.

Integration test fixtures live in tests/integration/conftest.py.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="postgresql://test:test@localhost:5432/test_cve",
        redis_url="redis://localhost:6379",
        environment="test",
        log_level="DEBUG",
        vulncheck_api_key="test_key",
        nvd_api_key="",
        nvd_request_delay_ms=0,
        nvd_request_delay_key_ms=0,
        auto_migrate=False,
    )


@pytest.fixture
def mock_pool() -> MagicMock:
    """Mock asyncpg pool for unit tests that don't need a real DB."""
    pool = MagicMock()
    conn = AsyncMock()
    pool.acquire = MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=conn),
            __aexit__=AsyncMock(return_value=False),
        )
    )
    pool.fetch = AsyncMock(return_value=[])
    pool.fetchrow = AsyncMock(return_value=None)
    pool.execute = AsyncMock()
    return pool


@pytest.fixture
def mock_redis() -> AsyncMock:
    """Mock redis.asyncio client for unit tests."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.setex = AsyncMock()
    redis.delete = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.scan_iter = AsyncMock(return_value=AsyncMock(__aiter__=lambda s: iter([])))
    return redis
