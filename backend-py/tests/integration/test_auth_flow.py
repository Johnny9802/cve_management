"""End-to-end JWT auth flow + RBAC enforcement (Sprint 1 — S1-tests).

Spins a minimal FastAPI app that mounts only the auth router plus a
single dummy protected route per role. Uses the testcontainer
Postgres pool so seed/login go through real SQL.

Why a minimal app rather than the production lifespan? The full
``app/main.py`` lifespan starts schedulers, opens upstream HTTP
clients, etc. — all noise for an auth test. Mounting only what we
need keeps the test fast and the failure modes legible.
"""
from __future__ import annotations

import asyncpg
import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport

from app.api.dependencies.auth import AuthUser, require_role
from app.api.routers.auth import router as auth_router
from app.core.config import Settings, get_settings
from app.services.auth_service import hash_password


JWT_SECRET = "integration-test-secret-not-real"


@pytest_asyncio.fixture(scope="module")
async def auth_app(db_pool: asyncpg.Pool):
    """Minimal app with auth router + per-role echo endpoints."""
    app = FastAPI()

    # Override settings to use a deterministic JWT secret. The lru_cache
    # on get_settings is bypassed via FastAPI's dependency_overrides.
    def _settings():
        return Settings(
            jwt_secret=JWT_SECRET,
            access_token_ttl_minutes=5,
            refresh_token_ttl_days=1,
            environment="development",
            database_url="postgresql://test/test",  # not used in routes
            redis_url="redis://test",
        )

    app.dependency_overrides[get_settings] = _settings
    app.state.db_pool = db_pool

    @app.get("/echo/analyst")
    async def echo_analyst(user: AuthUser = Depends(require_role("analyst"))):
        return {"who": user.email, "role": user.role}

    @app.get("/echo/admin")
    async def echo_admin(user: AuthUser = Depends(require_role("admin"))):
        return {"who": user.email, "role": user.role}

    app.include_router(auth_router)

    yield app


@pytest_asyncio.fixture
async def client(auth_app):
    transport = ASGITransport(app=auth_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def seeded_users(db_pool: asyncpg.Pool, clean_db):
    """Inserts one user per role and returns email+plaintext for login."""
    creds = {
        "admin":   ("admin@test", "admin-pw-strong"),
        "analyst": ("analyst@test", "analyst-pw-strong"),
        "viewer":  ("viewer@test", "viewer-pw-strong"),
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


async def _login(client: httpx.AsyncClient, email: str, password: str) -> dict:
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()


# ────────────────────────────────────────────────────── tests


@pytest.mark.asyncio
async def test_login_returns_tokens_and_records_audit(client, seeded_users, db_pool):
    email, pw = seeded_users["admin"]
    tokens = await _login(client, email, pw)

    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] > 0

    audit_count = await db_pool.fetchval(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login' AND actor_email = $1",
        email,
    )
    assert audit_count == 1


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401_and_audits_failure(
    client, seeded_users, db_pool
):
    email, _ = seeded_users["admin"]
    r = await client.post(
        "/api/auth/login",
        json={"email": email, "password": "wrong"},
    )
    assert r.status_code == 401

    fail_count = await db_pool.fetchval(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login_failed'",
    )
    assert fail_count == 1


@pytest.mark.asyncio
async def test_login_unknown_email_returns_401_with_generic_error(client, seeded_users):
    r = await client.post(
        "/api/auth/login",
        json={"email": "ghost@test", "password": "x"},
    )
    assert r.status_code == 401
    # Body must NOT distinguish "no such user" from "wrong password" —
    # otherwise we leak which emails exist.
    assert "Invalid email or password" in r.text


@pytest.mark.asyncio
async def test_protected_endpoint_requires_token(client, seeded_users):
    r = await client.get("/echo/analyst")
    assert r.status_code == 401
    assert r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.asyncio
async def test_protected_endpoint_accepts_valid_token(client, seeded_users):
    email, pw = seeded_users["analyst"]
    tokens = await _login(client, email, pw)

    r = await client.get(
        "/echo/analyst",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["who"] == email
    assert body["role"] == "analyst"


@pytest.mark.asyncio
async def test_admin_endpoint_rejects_analyst(client, seeded_users):
    email, pw = seeded_users["analyst"]
    tokens = await _login(client, email, pw)

    r = await client.get(
        "/echo/admin",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_endpoint_accepts_admin(client, seeded_users):
    email, pw = seeded_users["admin"]
    tokens = await _login(client, email, pw)

    r = await client.get(
        "/echo/admin",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_viewer_cannot_hit_analyst_endpoint(client, seeded_users):
    email, pw = seeded_users["viewer"]
    tokens = await _login(client, email, pw)

    r = await client.get(
        "/echo/analyst",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_implicitly_grants_analyst_routes(client, seeded_users):
    """`require_role("analyst")` must let admins through — admin is a
    superset of every other role per ADR 0001."""
    email, pw = seeded_users["admin"]
    tokens = await _login(client, email, pw)

    r = await client.get(
        "/echo/analyst",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_refresh_returns_new_token_pair_and_picks_up_role_change(
    client, seeded_users, db_pool
):
    email, pw = seeded_users["viewer"]
    tokens = await _login(client, email, pw)

    # Promote the user; the next refresh should issue an access token
    # carrying the new role without requiring a fresh login.
    await db_pool.execute(
        "UPDATE users SET role = 'analyst' WHERE email = $1", email,
    )

    r = await client.post(
        "/api/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert r.status_code == 200
    new_pair = r.json()

    me = await client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {new_pair['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["role"] == "analyst"


@pytest.mark.asyncio
async def test_refresh_with_inactive_user_rejected(client, seeded_users, db_pool):
    email, pw = seeded_users["viewer"]
    tokens = await _login(client, email, pw)

    await db_pool.execute(
        "UPDATE users SET is_active = FALSE WHERE email = $1", email,
    )

    r = await client.post(
        "/api/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert r.status_code == 401
