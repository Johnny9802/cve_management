"""Integration tests: real mutating routes behind ``require_role`` (S2.8).

Goal
----
Closes test gap TST-01 from the production-readiness review. Every
state-changing endpoint introduced or hardened in Sprint 1 must:

* return 401 without a bearer token,
* return 403 when the bearer carries the wrong role,
* return 200/201/204 with a valid bearer of the right role,
* validate input (422 on malformed body).

This file does NOT aim for one test per endpoint — that's the job of
the per-router suites (S2 follow-up). What it does cover are the
*authorization invariants* that, if regressed, would silently re-open
blocker B1 / R1.
"""
from __future__ import annotations

import asyncpg
import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport

from app.api.routers.auth import router as auth_router
from app.api.routers.findings import router as findings_router
from app.api.routers.products import router as products_router
from app.api.routers.system import router as system_router
from app.core.cache import create_redis
from app.core.config import Settings, get_settings
from app.services.auth_service import hash_password
from tests.integration.conftest import seed_cve, seed_finding, seed_product


JWT_SECRET = "router-integration-test-secret"


# Lightweight FakeRedis so /system/config doesn't need a real Valkey.
class FakeRedis:
    def __init__(self) -> None:
        self.kv: dict[str, str] = {}

    async def set(self, k: str, v: str) -> None:
        self.kv[k] = v

    async def get(self, k: str) -> str | None:
        return self.kv.get(k)

    async def keys(self, *_a, **_k):
        return list(self.kv.keys())

    async def aclose(self) -> None:  # pragma: no cover
        pass


@pytest_asyncio.fixture(scope="module")
async def app(db_pool: asyncpg.Pool):
    a = FastAPI()
    a.dependency_overrides[get_settings] = lambda: Settings(
        jwt_secret=JWT_SECRET,
        access_token_ttl_minutes=10,
        environment="development",
        database_url="postgresql://test",
        redis_url="redis://test",
    )
    a.state.db_pool = db_pool
    a.state.redis = FakeRedis()
    a.include_router(auth_router)
    a.include_router(findings_router)
    a.include_router(products_router)
    a.include_router(system_router)
    yield a


@pytest_asyncio.fixture
async def client(app):
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def users(db_pool: asyncpg.Pool, clean_db):
    """Seed admin + analyst + viewer; return their bearer tokens."""
    creds = {
        "admin":   ("admin@routers", "pw-admin-x9"),
        "analyst": ("analyst@routers", "pw-analyst-x9"),
        "viewer":  ("viewer@routers", "pw-viewer-x9"),
    }
    async with db_pool.acquire() as conn:
        for role, (email, pw) in creds.items():
            await conn.execute(
                """
                INSERT INTO users (email, password_hash, role, is_active)
                VALUES ($1, $2, $3, TRUE)
                """,
                email, hash_password(pw), role,
            )
    return creds


async def _token(client: httpx.AsyncClient, email: str, password: str) -> str:
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()["access_token"]


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ───────────────────────────────────────────── findings.update_finding


@pytest.mark.asyncio
async def test_finding_patch_requires_token(client, users, db_pool):
    async with db_pool.acquire() as conn:
        pid = await seed_product(conn)
        cid = await seed_cve(conn)
        await seed_finding(conn, pid, cid, status="open")

    r = await client.patch(f"/api/findings/{pid}/{cid}", json={"status": "in_review"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_finding_patch_rejects_viewer(client, users, db_pool):
    async with db_pool.acquire() as conn:
        pid = await seed_product(conn)
        cid = await seed_cve(conn)
        await seed_finding(conn, pid, cid, status="open")

    email, pw = users["viewer"]
    token = await _token(client, email, pw)
    r = await client.patch(
        f"/api/findings/{pid}/{cid}",
        json={"status": "in_review"},
        headers=_h(token),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_finding_patch_succeeds_for_analyst_and_audits_actor(client, users, db_pool):
    async with db_pool.acquire() as conn:
        pid = await seed_product(conn)
        cid = await seed_cve(conn)
        await seed_finding(conn, pid, cid, status="open")

    email, pw = users["analyst"]
    token = await _token(client, email, pw)
    r = await client.patch(
        f"/api/findings/{pid}/{cid}",
        json={"status": "in_review"},
        headers=_h(token),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "in_review"

    # Audit row was written, and the actor is the JWT subject — not a
    # client-supplied string.
    actor = await db_pool.fetchval(
        "SELECT actor_email FROM audit_log WHERE action = 'finding.status_change' "
        "ORDER BY id DESC LIMIT 1",
    )
    assert actor == email


@pytest.mark.asyncio
async def test_finding_patch_validates_status(client, users, db_pool):
    async with db_pool.acquire() as conn:
        pid = await seed_product(conn)
        cid = await seed_cve(conn)
        await seed_finding(conn, pid, cid, status="open")

    email, pw = users["analyst"]
    token = await _token(client, email, pw)
    r = await client.patch(
        f"/api/findings/{pid}/{cid}",
        json={"status": "not_a_status"},
        headers=_h(token),
    )
    assert r.status_code == 422


# ───────────────────────────────────────────── system.update_config (admin only)


@pytest.mark.asyncio
async def test_system_config_patch_rejects_anonymous(client, users):
    r = await client.patch(
        "/api/system/config",
        json={"key": "NVD_API_KEY", "value": "x"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_system_config_patch_rejects_analyst(client, users):
    email, pw = users["analyst"]
    token = await _token(client, email, pw)
    r = await client.patch(
        "/api/system/config",
        json={"key": "NVD_API_KEY", "value": "x"},
        headers=_h(token),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_system_config_patch_accepts_admin(client, users, app):
    email, pw = users["admin"]
    token = await _token(client, email, pw)
    r = await client.patch(
        "/api/system/config",
        json={"key": "NVD_API_KEY", "value": "secret-rotated"},
        headers=_h(token),
    )
    assert r.status_code == 200
    assert app.state.redis.kv["cfg:NVD_API_KEY"] == "secret-rotated"


@pytest.mark.asyncio
async def test_system_config_patch_unknown_key_is_400(client, users):
    email, pw = users["admin"]
    token = await _token(client, email, pw)
    r = await client.patch(
        "/api/system/config",
        json={"key": "NUCLEAR_LAUNCH", "value": "x"},
        headers=_h(token),
    )
    assert r.status_code == 400


# ───────────────────────────────────────────── products.create + delete


@pytest.mark.asyncio
async def test_product_post_requires_analyst(client, users):
    r = await client.post("/api/products", json={"name": "x", "version": "1.0"})
    assert r.status_code == 401

    email, pw = users["viewer"]
    token = await _token(client, email, pw)
    r = await client.post(
        "/api/products",
        json={"name": "x", "version": "1.0"},
        headers=_h(token),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_product_create_then_delete_audited(client, users, db_pool):
    email, pw = users["analyst"]
    token = await _token(client, email, pw)

    create = await client.post(
        "/api/products",
        json={"name": "nginx-test", "version": "1.0.0", "vendor": "nginx"},
        headers=_h(token),
    )
    assert create.status_code == 201
    pid = create.json()["id"]

    # Audit row from the create.
    rows = await db_pool.fetch(
        "SELECT action, actor_email FROM audit_log WHERE target_type='product' "
        "AND target_id = $1 ORDER BY id",
        str(pid),
    )
    actions = [r["action"] for r in rows]
    assert "product.create" in actions
    assert all(r["actor_email"] == email for r in rows)

    # Now delete and confirm the audit row is written *before* the
    # cascade obliterates everything else (S1.7 design).
    deleted = await client.delete(f"/api/products/{pid}", headers=_h(token))
    assert deleted.status_code == 200

    actions_after = await db_pool.fetch(
        "SELECT action FROM audit_log WHERE target_type='product' AND target_id=$1 "
        "ORDER BY id",
        str(pid),
    )
    assert "product.delete" in [r["action"] for r in actions_after]
