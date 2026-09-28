"""Identifier and token helpers."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid

API_KEY_PREFIX = "rsk_"
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def clean_correlation_id(candidate: str | None) -> str:
    """Accept a caller-supplied request ID only if it is short and harmless; else make one."""
    if candidate and _CORRELATION_RE.match(candidate):
        return candidate
    return new_correlation_id()


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(plaintext, prefix, sha256_hex)``. Only the hash is ever stored."""
    token = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return token, token[:12], hash_api_key(token)


def hash_api_key(token: str) -> str:
    # A fast hash is appropriate here: the key has 256 bits of entropy, so it cannot be
    # brute-forced, and verification happens on every request.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def manual_external_id() -> str:
    """External ID for listings entered by hand without a marketplace URL."""
    return f"manual-{uuid.uuid4().hex[:16]}"
