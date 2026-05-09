"""Symmetric encryption for sensitive at-rest fields (Sprint 4 — S4.7).

Currently used only for the webhook signing secret (``webhooks.secret_encrypted``).
The interface is deliberately tiny so adding more fields later means
"call ``encrypt(plaintext)`` / ``decrypt(token)`` in the right place"
and nothing else.

Algorithm: ``cryptography.fernet.Fernet`` (AES-128 CBC + HMAC-SHA256
+ versioned token). Keys are 32 raw bytes encoded as URL-safe base64;
the operator generates one with::

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Behaviour when no key is configured (dev / portfolio default):

* ``is_configured()`` returns False.
* ``encrypt`` raises ``CryptoNotConfigured`` so the caller can decide
  whether to fall back to plaintext (development) or refuse the write
  (production — see app/api/routers/webhooks.py for the policy).
* ``decrypt`` raises ``CryptoNotConfigured`` too, because a token can
  only be decrypted with the same key that produced it.
"""
from __future__ import annotations

from functools import lru_cache

import structlog
from cryptography.fernet import Fernet, InvalidToken

logger = structlog.get_logger(__name__)


class CryptoNotConfigured(RuntimeError):
    """Raised when an encrypt/decrypt is requested but no key is set."""


class CryptoError(RuntimeError):
    """Raised on decryption failure (malformed or wrong-key token)."""


@lru_cache(maxsize=1)
def _fernet(key: str) -> Fernet:
    # Cached so we don't parse the base64 key on every call.
    return Fernet(key.encode("utf-8"))


def is_configured(key: str) -> bool:
    return bool(key)


def encrypt(plaintext: str, *, key: str) -> bytes:
    if not key:
        raise CryptoNotConfigured("WEBHOOK_ENC_KEY is empty")
    return _fernet(key).encrypt(plaintext.encode("utf-8"))


def decrypt(token: bytes, *, key: str) -> str:
    if not key:
        raise CryptoNotConfigured("WEBHOOK_ENC_KEY is empty")
    try:
        return _fernet(key).decrypt(bytes(token)).decode("utf-8")
    except InvalidToken as err:
        # Don't leak the token in the exception message — could end up
        # in a structured log otherwise.
        raise CryptoError("invalid or wrong-key ciphertext") from err
