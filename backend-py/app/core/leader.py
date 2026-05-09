"""Redis-based single-leader election (Sprint 4 — S4.8).

Closes blocker R3: the scheduler runs cron jobs (delta sync, EPSS
refresh, KEV refresh, snapshot, retention) that *must* execute
exactly once per cluster, not per replica. Without a coordinator,
N replicas would N-times the upstream API quota and write N
duplicate snapshot rows per day.

Algorithm
---------
SET NX EX with periodic refresh, no Redlock — this is portfolio-
grade leader election: a single shared Redis (we already require it)
and a 30-second TTL refreshed every 10 seconds. If the leader
crashes, the lock expires within 30 seconds and any other replica
takes over on the next refresh tick. Brief gaps are acceptable
because every cron job is idempotent (delta_sync uses ``last_success_at``
checkpoints, snapshots have UNIQUE(captured_on), etc.).

Failure modes the design tolerates:
  * Redis down → ``is_leader`` returns False, no replica runs the
    cron jobs. They resume when Redis recovers.
  * Network split → the leader can't refresh, lock expires, a new
    leader emerges. Worst case: a single duplicate run during the
    overlap. All scheduled jobs are idempotent for exactly this
    reason.
  * Process crash → next refresh tick fails the SET XX, replica
    promotes.

The lifespan calls ``acquire`` once at startup, then schedules a
periodic refresh via the same APScheduler instance the cron jobs
ride on. ``release`` is called on graceful shutdown.
"""
from __future__ import annotations

import asyncio
import os
import socket
import uuid

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger(__name__)


_LOCK_KEY = "scheduler:leader"
_TTL_SECONDS = 30
_REFRESH_INTERVAL_SECONDS = 10


def _node_id() -> str:
    """Stable-per-process identifier the leader writes into the lock
    so logs/metrics can tell *who* is leading."""
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


class LeaderElector:
    def __init__(self, redis: Redis, *, lock_key: str = _LOCK_KEY) -> None:
        self._redis = redis
        self._lock_key = lock_key
        self._node = _node_id()
        self._is_leader = False
        self._refresh_task: asyncio.Task[None] | None = None

    @property
    def node_id(self) -> str:
        return self._node

    @property
    def is_leader(self) -> bool:
        return self._is_leader

    async def acquire(self) -> bool:
        """Try to take the lock once. Returns True if we won the
        election. Idempotent — calling on a leader is a no-op."""
        if self._is_leader:
            return True
        try:
            ok = await self._redis.set(
                self._lock_key, self._node, nx=True, ex=_TTL_SECONDS,
            )
        except Exception as exc:
            logger.warning("leader.acquire_failed", error=str(exc))
            return False
        self._is_leader = bool(ok)
        if self._is_leader:
            logger.info("leader.acquired", node=self._node)
        return self._is_leader

    async def refresh(self) -> bool:
        """Tick the lock TTL forward; relinquishes leadership if the
        lock has been stolen (e.g. our refresh missed the previous TTL).

        Lua keeps the check + extend atomic — without it a non-leader
        could refresh the leader's lock by accident.
        """
        if not self._is_leader:
            # Lost or never had the lock — try to take it again.
            return await self.acquire()
        lua = (
            "if redis.call('GET', KEYS[1]) == ARGV[1] then "
            "  return redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2])) "
            "else "
            "  return 0 "
            "end"
        )
        try:
            res = await self._redis.eval(lua, 1, self._lock_key, self._node, _TTL_SECONDS)
        except Exception as exc:
            logger.warning("leader.refresh_failed", error=str(exc))
            return self._is_leader
        if not res:
            logger.warning("leader.lost", node=self._node)
            self._is_leader = False
        return self._is_leader

    async def release(self) -> None:
        """Best-effort lock release on graceful shutdown."""
        if not self._is_leader:
            return
        lua = (
            "if redis.call('GET', KEYS[1]) == ARGV[1] then "
            "  return redis.call('DEL', KEYS[1]) "
            "else "
            "  return 0 "
            "end"
        )
        try:
            await self._redis.eval(lua, 1, self._lock_key, self._node)
            logger.info("leader.released", node=self._node)
        except Exception as exc:
            logger.warning("leader.release_failed", error=str(exc))
        finally:
            self._is_leader = False

    def start_background_refresh(self) -> asyncio.Task[None]:
        """Spawn a forever-task that calls refresh() every 10s.
        The lifespan stores the returned Task on app.state so it's
        cancelled cleanly on shutdown."""
        async def _loop() -> None:
            while True:
                await asyncio.sleep(_REFRESH_INTERVAL_SECONDS)
                try:
                    await self.refresh()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("leader.refresh_loop_error", error=str(exc))

        self._refresh_task = asyncio.create_task(_loop(), name="leader-refresh")
        return self._refresh_task

    async def stop_background_refresh(self) -> None:
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except (asyncio.CancelledError, Exception):
                pass
            self._refresh_task = None
