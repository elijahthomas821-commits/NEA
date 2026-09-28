"""A small, synchronous Telegram Bot API client (httpx).

Security: the bot token is part of every Bot API URL (``/bot<token>/<method>``), so this module
never puts a URL into a log event or an exception message, and it drops the underlying httpx
exception (whose request carries the URL) instead of chaining it. The log redactor also knows
the token, as a second line of defence. The client only ever talks to the Bot API.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

TEXT_LIMIT = 4096
CALLBACK_TEXT_LIMIT = 200
_FILE_PATH_RE = re.compile(r"[A-Za-z0-9_\-./]{1,256}")


class TelegramError(Exception):
    """A Bot API call failed. ``retryable`` says whether trying again later can help."""

    retryable = False

    def __init__(self, description: str, *, error_code: int | None = None) -> None:
        super().__init__(description)
        self.description = description
        self.error_code = error_code


class TelegramRetryAfterError(TelegramError):
    """429: flood control. Wait ``retry_after`` seconds before the next call."""

    retryable = True

    def __init__(self, description: str, *, retry_after: int) -> None:
        super().__init__(description, error_code=429)
        self.retry_after = max(1, retry_after)


class TelegramUnavailableError(TelegramError):
    """Network failure, timeout or a 5xx from Telegram."""

    retryable = True


class TelegramConflictError(TelegramError):
    """409: a webhook is set, or another process is polling with the same token."""

    retryable = True


class TelegramUnauthorizedError(TelegramError):
    """401: the bot token is invalid or has been revoked."""


class TelegramRejectedError(TelegramError):
    """400/403/404: the request itself is wrong (unknown chat, bot blocked, bad markup)."""

    @property
    def not_modified(self) -> bool:
        return "message is not modified" in self.description.lower()


def _clean(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in params.items() if v is not None}


class TelegramClient:
    def __init__(
        self,
        token: str,
        *,
        api_base: str = "https://api.telegram.org",
        timeout: float = 15.0,
        http: httpx.Client | None = None,
    ) -> None:
        if not token:
            raise ValueError("a bot token is required")
        self._token = token
        self._base = api_base.rstrip("/")
        self._timeout = timeout
        self._http = http or httpx.Client(
            timeout=httpx.Timeout(timeout, connect=5.0), follow_redirects=False
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> TelegramClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ transport

    def call(
        self, method: str, params: dict[str, Any] | None = None, *, timeout: float | None = None
    ) -> Any:
        url = f"{self._base}/bot{self._token}/{method}"
        try:
            response = self._http.post(url, json=_clean(params or {}), timeout=timeout)
        except httpx.TimeoutException:
            raise TelegramUnavailableError(f"{method}: timed out") from None
        except httpx.HTTPError as exc:
            raise TelegramUnavailableError(f"{method}: {type(exc).__name__}") from None
        return _result(method, response)

    # ------------------------------------------------------------------ methods

    def get_me(self) -> dict[str, Any]:
        result: dict[str, Any] = self.call("getMe")
        return result

    def send_message(
        self,
        chat_id: int,
        text: str,
        *,
        reply_markup: dict[str, Any] | None = None,
        reply_to_message_id: int | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = self.call(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": text[:TEXT_LIMIT],
                "parse_mode": "HTML",
                "link_preview_options": {"is_disabled": True},
                "reply_markup": reply_markup,
                "reply_parameters": (
                    {"message_id": reply_to_message_id, "allow_sending_without_reply": True}
                    if reply_to_message_id
                    else None
                ),
            },
        )
        return result

    def edit_message_reply_markup(
        self, chat_id: int, message_id: int, reply_markup: dict[str, Any] | None
    ) -> None:
        try:
            self.call(
                "editMessageReplyMarkup",
                {
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "reply_markup": reply_markup or {"inline_keyboard": []},
                },
            )
        except TelegramRejectedError as exc:
            if not exc.not_modified:
                raise

    def answer_callback_query(
        self, callback_query_id: str, text: str | None = None, *, show_alert: bool = False
    ) -> None:
        self.call(
            "answerCallbackQuery",
            {
                "callback_query_id": callback_query_id,
                "text": text[:CALLBACK_TEXT_LIMIT] if text else None,
                "show_alert": show_alert or None,
            },
        )

    def get_updates(
        self, *, offset: int | None, timeout: int, allowed_updates: list[str]
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self.call(
            "getUpdates",
            {"offset": offset, "timeout": timeout, "allowed_updates": allowed_updates},
            timeout=timeout + 10,
        )
        return result

    def set_webhook(
        self, url: str, *, secret_token: str, allowed_updates: list[str], max_connections: int = 1
    ) -> None:
        self.call(
            "setWebhook",
            {
                "url": url,
                "secret_token": secret_token,
                "allowed_updates": allowed_updates,
                "max_connections": max_connections,
            },
        )

    def delete_webhook(self) -> None:
        self.call("deleteWebhook", {"drop_pending_updates": False})

    def set_my_commands(self, commands: list[tuple[str, str]]) -> None:
        self.call(
            "setMyCommands",
            {"commands": [{"command": c, "description": d} for c, d in commands]},
        )

    def get_file(self, file_id: str) -> dict[str, Any]:
        result: dict[str, Any] = self.call("getFile", {"file_id": file_id})
        return result

    def download_file(self, file_path: str, *, max_bytes: int) -> bytes:
        """Download a file Telegram holds for the bot (a photo the operator sent)."""
        if not _FILE_PATH_RE.fullmatch(file_path) or ".." in file_path:
            raise TelegramRejectedError("unexpected file path from Telegram")
        url = f"{self._base}/file/bot{self._token}/{file_path}"
        try:
            with self._http.stream("GET", url) as response:
                if response.status_code >= 500:
                    raise TelegramUnavailableError(f"file download: HTTP {response.status_code}")
                if response.status_code != 200:
                    raise TelegramRejectedError(
                        f"file download: HTTP {response.status_code}",
                        error_code=response.status_code,
                    )
                declared = response.headers.get("content-length")
                if declared is not None and declared.isdigit() and int(declared) > max_bytes:
                    raise FileTooLargeError(max_bytes)
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise FileTooLargeError(max_bytes)
                    chunks.append(chunk)
        except httpx.TimeoutException:
            raise TelegramUnavailableError("file download: timed out") from None
        except httpx.HTTPError as exc:
            raise TelegramUnavailableError(f"file download: {type(exc).__name__}") from None
        return b"".join(chunks)


class FileTooLargeError(TelegramRejectedError):
    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"file larger than {max_bytes // (1024 * 1024)} MB")


def _result(method: str, response: httpx.Response) -> Any:
    status = response.status_code
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        if status >= 500:
            raise TelegramUnavailableError(f"{method}: HTTP {status}", error_code=status)
        raise TelegramRejectedError(f"{method}: HTTP {status}", error_code=status)
    if body.get("ok") is True:
        return body.get("result")

    code = body.get("error_code")
    code = code if isinstance(code, int) else status
    description = f"{method}: {str(body.get('description') or f'HTTP {code}')[:300]}"
    parameters = body.get("parameters") if isinstance(body.get("parameters"), dict) else {}
    retry_after = parameters.get("retry_after") if parameters else None
    if code == 429 or isinstance(retry_after, int):
        raise TelegramRetryAfterError(
            description, retry_after=retry_after if isinstance(retry_after, int) else 5
        )
    if code == 401:
        raise TelegramUnauthorizedError(description, error_code=code)
    if code == 409:
        raise TelegramConflictError(description, error_code=code)
    if code >= 500:
        raise TelegramUnavailableError(description, error_code=code)
    raise TelegramRejectedError(description, error_code=code)
