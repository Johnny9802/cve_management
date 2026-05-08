"""FastAPI Depends() for JWT auth + role gating (Sprint 1 — S1.2b).

Usage:

    @router.post("/things")
    async def create_thing(
        body: ThingIn,
        user: AuthUser = Depends(require_role("admin")),
    ):
        ...

* ``get_current_user`` — resolves the JWT, returns ``AuthUser``.
  401 on missing / invalid / expired token.
* ``require_role(*roles)`` — composes with ``get_current_user`` and
  also enforces the role allow-list. 403 if authenticated but not
  authorized.
* ``optional_current_user`` — returns ``AuthUser | None``; for routes
  that behave differently for anonymous vs authenticated callers
  without forcing auth.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings
from app.services.auth_service import (
    ExpiredSignatureError,
    InvalidTokenError,
    decode_token,
)


@dataclass(frozen=True)
class AuthUser:
    id: int
    email: str
    role: str


# ``auto_error=False`` so we can return our own 401 with WWW-Authenticate
# instead of the FastAPI default which omits the header.
_bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    request: Request,  # noqa: ARG001 — kept for symmetry / future ip-binding checks
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> AuthUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized("Missing bearer token")
    try:
        payload = decode_token(
            credentials.credentials,
            secret=settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
            expected_type="access",
        )
    except ExpiredSignatureError as err:
        raise _unauthorized("Token expired") from err
    except InvalidTokenError as err:
        raise _unauthorized("Invalid token") from err

    return AuthUser(id=payload.sub, email=payload.email, role=payload.role)


async def optional_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> AuthUser | None:
    """Like ``get_current_user`` but never raises on missing/invalid
    credentials — used by routes that want to log the actor when
    available without forcing login."""
    if credentials is None:
        return None
    try:
        return await get_current_user(request, credentials, settings)
    except HTTPException:
        return None


def require_role(*allowed_roles: str):
    """Factory that returns a Depends-compatible callable enforcing
    the role allow-list. ``admin`` is implicitly granted everything.
    """
    if not allowed_roles:
        raise ValueError("require_role() needs at least one role")

    allowed = set(allowed_roles)

    async def _checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if user.role == "admin" or user.role in allowed:
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{user.role}' is not authorized; required one of {sorted(allowed)}",
        )

    return _checker
