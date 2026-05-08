"""JWT + bcrypt password handling (Sprint 1 — S1.2a).

This module is the single source of truth for:

* Password hashing / verification (bcrypt with the library default
  cost factor of 12).
* JWT token encoding / decoding for both ``access`` and ``refresh``
  tokens. The token type is part of the JWT payload so a refresh
  token cannot be used as an access token (and vice-versa).

The design rationale lives in ``docs/adr/0001-auth-strategy.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

# JWT exceptions re-exported so consumers don't have to know we use
# pyjwt under the hood.
from jwt import ExpiredSignatureError, InvalidTokenError

__all__ = [
    "TokenPayload",
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "ExpiredSignatureError",
    "InvalidTokenError",
]


@dataclass(frozen=True)
class TokenPayload:
    """Decoded, validated JWT payload."""

    sub: int          # user id
    email: str
    role: str
    type: str         # "access" | "refresh"
    exp: int
    iat: int


# ────────────────────────────────────────────────────────── passwords


def hash_password(plaintext: str) -> str:
    """Return a bcrypt hash of ``plaintext`` (algo + cost + salt + hash).

    The cost factor is the bcrypt library default (12). Increasing it
    in the future requires no schema change because verify reads the
    cost from the hash itself; existing users get re-hashed on next
    login if you wire the upgrade in ``verify_password``'s caller.
    """
    if not plaintext:
        raise ValueError("password must not be empty")
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plaintext: str, hashed: str) -> bool:
    """Constant-time check. Returns False on any decoding error so a
    malformed hash in the DB doesn't crash the login flow."""
    if not plaintext or not hashed:
        return False
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ────────────────────────────────────────────────────────── JWT


def _now_utc() -> datetime:
    return datetime.now(tz=UTC)


def create_access_token(
    *,
    user_id: int,
    email: str,
    role: str,
    secret: str,
    algorithm: str = "HS256",
    ttl_minutes: int = 60,
) -> str:
    """Mint a short-lived bearer token. The role claim is consulted by
    ``require_role`` on every request."""
    now = _now_utc()
    payload: dict[str, Any] = {
        # RFC 7519 / pyjwt 2.10 require ``sub`` to be a string.
        "sub": str(user_id),
        "email": email,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def create_refresh_token(
    *,
    user_id: int,
    secret: str,
    algorithm: str = "HS256",
    ttl_days: int = 7,
) -> str:
    """Refresh tokens carry only the subject — every refresh re-reads
    role and email from the DB so a role change takes effect on the
    next refresh, not just on next login."""
    now = _now_utc()
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=ttl_days)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(
    token: str,
    *,
    secret: str,
    algorithm: str = "HS256",
    expected_type: str | None = None,
) -> TokenPayload:
    """Decode + validate a JWT. Raises:

    * ``jwt.ExpiredSignatureError`` if past exp.
    * ``jwt.InvalidTokenError`` if malformed, signature mismatch, or
      ``expected_type`` mismatch.
    """
    decoded: dict[str, Any] = jwt.decode(token, secret, algorithms=[algorithm])
    if expected_type is not None and decoded.get("type") != expected_type:
        raise InvalidTokenError(
            f"token type mismatch: expected {expected_type!r}, got {decoded.get('type')!r}"
        )
    return TokenPayload(
        sub=int(decoded["sub"]),
        email=str(decoded.get("email", "")),
        role=str(decoded.get("role", "")),
        type=str(decoded["type"]),
        exp=int(decoded["exp"]),
        iat=int(decoded["iat"]),
    )
