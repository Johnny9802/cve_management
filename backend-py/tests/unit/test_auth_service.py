"""Unit tests for auth_service: bcrypt + JWT happy and edge cases."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.services.auth_service import (
    ExpiredSignatureError,
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

SECRET = "test-secret-not-used-anywhere-real"


# ────────────────────────────────────────────────────── passwords


class TestPasswordHashing:
    def test_hash_then_verify_succeeds(self):
        hashed = hash_password("hunter2")
        assert verify_password("hunter2", hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False

    def test_empty_plaintext_rejected_on_hash(self):
        with pytest.raises(ValueError):
            hash_password("")

    def test_empty_plaintext_returns_false_on_verify(self):
        # We don't crash on empty inputs — saves a 500 if a malformed
        # request body slips past validation upstream.
        hashed = hash_password("x")
        assert verify_password("", hashed) is False

    def test_malformed_hash_returns_false(self):
        assert verify_password("password", "not-a-bcrypt-hash") is False

    def test_two_hashes_of_same_password_differ(self):
        # bcrypt salts every hash, so identical passwords must hash
        # differently (otherwise rainbow tables would break us).
        a = hash_password("same")
        b = hash_password("same")
        assert a != b
        assert verify_password("same", a)
        assert verify_password("same", b)


# ────────────────────────────────────────────────────── JWT roundtrip


class TestJwtRoundtrip:
    def test_access_token_roundtrip(self):
        token = create_access_token(
            user_id=42, email="alice@example.com", role="analyst",
            secret=SECRET,
        )
        payload = decode_token(token, secret=SECRET, expected_type="access")
        assert payload.sub == 42
        assert payload.email == "alice@example.com"
        assert payload.role == "analyst"
        assert payload.type == "access"

    def test_refresh_token_roundtrip(self):
        token = create_refresh_token(user_id=7, secret=SECRET)
        payload = decode_token(token, secret=SECRET, expected_type="refresh")
        assert payload.sub == 7
        assert payload.type == "refresh"

    def test_access_token_rejected_when_refresh_expected(self):
        token = create_access_token(
            user_id=1, email="x@y.z", role="viewer", secret=SECRET,
        )
        with pytest.raises(InvalidTokenError):
            decode_token(token, secret=SECRET, expected_type="refresh")

    def test_refresh_token_rejected_when_access_expected(self):
        token = create_refresh_token(user_id=1, secret=SECRET)
        with pytest.raises(InvalidTokenError):
            decode_token(token, secret=SECRET, expected_type="access")

    def test_wrong_secret_rejected(self):
        token = create_access_token(
            user_id=1, email="x@y.z", role="admin", secret=SECRET,
        )
        with pytest.raises(InvalidTokenError):
            decode_token(token, secret="other-secret")

    def test_expired_token_raises(self):
        # Forge a token with exp in the past by encoding directly.
        past = datetime.now(tz=UTC) - timedelta(minutes=5)
        token = jwt.encode(
            {
                "sub": "1",
                "email": "x@y.z",
                "role": "viewer",
                "type": "access",
                "iat": int((past - timedelta(minutes=1)).timestamp()),
                "exp": int(past.timestamp()),
            },
            SECRET,
            algorithm="HS256",
        )
        with pytest.raises(ExpiredSignatureError):
            decode_token(token, secret=SECRET)

    def test_sub_is_string_in_payload(self):
        # PyJWT 2.10 enforces RFC 7519 — sub must be a string.
        # Regression guard for the bug we hit during S1.2 wiring.
        token = create_access_token(
            user_id=999, email="x@y.z", role="admin", secret=SECRET,
        )
        raw = jwt.decode(token, SECRET, algorithms=["HS256"])
        assert isinstance(raw["sub"], str)
