"""Auth router — /api/auth (Sprint 1 — S1.2b).

Endpoints
---------
* ``POST /api/auth/login``      — exchange email+password for tokens
* ``POST /api/auth/refresh``    — exchange refresh token for new access
* ``GET  /api/auth/me``         — current user info (requires auth)

Audit log
---------
Successful logins write an ``auth.login`` audit entry with IP +
user-agent. Failed logins write ``auth.login_failed`` so brute-force
attempts are visible in governance reports. The audit row is best-
effort and never blocks the login response.
"""
from __future__ import annotations

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from app.api.dependencies.auth import AuthUser, get_current_user
from app.core.config import Settings, get_settings
from app.services import audit
from app.services.auth_service import (
    ExpiredSignatureError,
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


# ────────────────────────────────────────────────────────── schemas


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=4096)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int     # seconds — convenience for the FE


class MeResponse(BaseModel):
    id: int
    email: str
    role: str


# ────────────────────────────────────────────────────────── helpers


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.db_pool


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ────────────────────────────────────────────────────────── routes


@router.post("/login", response_model=TokenPair)
async def login(
    body: LoginRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(_get_pool),
    settings: Settings = Depends(get_settings),
) -> TokenPair:
    email = body.email.lower()
    row = await pool.fetchrow(
        "SELECT id, email, password_hash, role, is_active FROM users WHERE email = $1",
        email,
    )

    if row is None or not row["is_active"] or not verify_password(body.password, row["password_hash"]):
        # Best-effort audit; fire-and-forget pattern outside a transaction.
        await audit.record(
            pool,
            action="auth.login_failed",
            target_type="user",
            target_id=email,
            actor_email=email,
            actor_role="anonymous",
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        # Generic message — never leak whether the email exists.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Update last_login_at and audit in one transaction so a successful
    # response always has both side-effects committed atomically.
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1", row["id"]
        )
        await audit.record_in_tx(
            conn,
            action="auth.login",
            target_type="user",
            target_id=str(row["id"]),
            actor_email=row["email"],
            actor_role=row["role"],
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    access = create_access_token(
        user_id=row["id"],
        email=row["email"],
        role=row["role"],
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        ttl_minutes=settings.access_token_ttl_minutes,
    )
    refresh = create_refresh_token(
        user_id=row["id"],
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        ttl_days=settings.refresh_token_ttl_days,
    )
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_minutes * 60,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    body: RefreshRequest,
    pool: asyncpg.Pool = Depends(_get_pool),
    settings: Settings = Depends(get_settings),
) -> TokenPair:
    try:
        payload = decode_token(
            body.refresh_token,
            secret=settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
            expected_type="refresh",
        )
    except ExpiredSignatureError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        ) from err
    except InvalidTokenError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from err

    # Re-read role + email from the DB so a role change applied since
    # the refresh token was issued takes effect immediately.
    row = await pool.fetchrow(
        "SELECT id, email, role, is_active FROM users WHERE id = $1",
        payload.sub,
    )
    if row is None or not row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer active",
        )

    access = create_access_token(
        user_id=row["id"],
        email=row["email"],
        role=row["role"],
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        ttl_minutes=settings.access_token_ttl_minutes,
    )
    new_refresh = create_refresh_token(
        user_id=row["id"],
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        ttl_days=settings.refresh_token_ttl_days,
    )
    return TokenPair(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=settings.access_token_ttl_minutes * 60,
    )


@router.get("/me", response_model=MeResponse)
async def me(user: AuthUser = Depends(get_current_user)) -> MeResponse:
    return MeResponse(id=user.id, email=user.email, role=user.role)
