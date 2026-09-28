"""Secret redaction for logs, error messages and stored error summaries.

Three layers, applied in order:

1. Exact values registered at start-up (bot token, AI key, DB password, webhook secret).
2. Pattern rules for secrets we may not have registered (Telegram token shapes inside Bot API
   URLs, ``sk-ant-`` keys, our own ``rsk_`` API keys, bearer tokens, credentials in URLs,
   secret-looking query parameters).
3. Key-based rules for structured data: values under keys such as ``password`` or ``api_key``.

The Telegram bot token appears inside every Bot API URL (``/bot<token>/sendMessage``) and httpx
logs request URLs, so layer 2 is mandatory, not optional.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping, MutableMapping
from typing import Any

REDACTED = "***"

_registered: set[str] = set()
_lock = threading.Lock()

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Telegram bot token, bare or inside /bot<token>/ URLs. No \b before the digits: in
    # "/bot123:ABC" the "t" and "1" are both word characters, so a boundary never matches.
    (re.compile(r"(?<![0-9])\d{6,12}:[A-Za-z0-9_-]{30,}"), "<telegram-token:***>"),
    # Anthropic API keys.
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}"), "sk-ant-***"),
    # This application's API keys (see app.core.ids.generate_api_key).
    (re.compile(r"\brsk_[A-Za-z0-9_-]{16,}"), "rsk_***"),
    # Bearer tokens in headers or free text.
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1***"),
    # user:password@host in URLs.
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s/]+@"), r"\1***@"),
    # Secret-looking query parameters.
    (
        re.compile(
            r"(?i)([?&](?:token|api_key|apikey|key|secret|password|access_token|sig)=)[^&\s#]+"
        ),
        r"\1***",
    ),
]

_SENSITIVE_KEY = re.compile(
    r"(?i)(^|_|-)(password|passwd|secret|api[_-]?key|authorization|cookie|dsn|credential|"
    r"bot[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?token|webhook[_-]?token)s?($|_|-)"
)


def register_secret(value: str | None) -> None:
    """Register an exact secret value so it is scrubbed wherever it appears."""
    if not value or len(value) < 6:
        return
    with _lock:
        _registered.add(value)


def clear_registered_secrets() -> None:
    """Testing helper."""
    with _lock:
        _registered.clear()


def redact_text(text: str) -> str:
    if not text:
        return text
    with _lock:
        secrets = sorted(_registered, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY.search(key))


def redact_value(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact strings inside dicts, lists and tuples."""
    if _depth > 12:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes):
        return redact_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and is_sensitive_key(key) and item not in (None, "", 0):
                out[key] = REDACTED
            else:
                out[key] = redact_value(item, _depth=_depth + 1)
        return out
    if isinstance(value, list):
        return [redact_value(item, _depth=_depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, _depth=_depth + 1) for item in value)
    if isinstance(value, BaseException):
        return redact_text(f"{type(value).__name__}: {value}")
    return value


def redact_processor(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor: scrub every value in the event dict."""
    for key in list(event_dict.keys()):
        value = event_dict[key]
        if is_sensitive_key(key) and isinstance(value, str | bytes) and value:
            event_dict[key] = REDACTED
        else:
            event_dict[key] = redact_value(value)
    return event_dict


def safe_error_summary(exc: BaseException, *, limit: int = 500) -> str:
    """A short, redacted description of an exception suitable for storing in the database."""
    text = redact_text(f"{type(exc).__name__}: {exc}")
    return text if len(text) <= limit else text[: limit - 3] + "..."
