"""Telegram webhook (only when TELEGRAM_MODE=webhook; polling needs no inbound endpoint)."""

from __future__ import annotations

import hmac
from typing import Annotated, Any

from fastapi import APIRouter, Body, Header, Request

from app.core.errors import AuthenticationError, NotFoundError

router = APIRouter(prefix="/telegram", tags=["telegram"], include_in_schema=False)


@router.post("/webhook")
def telegram_webhook(
    request: Request,
    payload: Annotated[dict[str, Any], Body()],
    secret_token: Annotated[str | None, Header(alias="X-Telegram-Bot-Api-Secret-Token")] = None,
) -> dict[str, bool]:
    settings = request.app.state.settings
    bot = request.app.state.telegram_bot
    if settings.telegram_mode != "webhook" or bot is None:
        raise NotFoundError("not found")
    expected = settings.telegram_webhook_secret
    # Constant-time comparison: the secret is what proves the request came from Telegram.
    if (
        expected is None
        or secret_token is None
        or not hmac.compare_digest(
            secret_token.encode("utf-8"), expected.get_secret_value().encode("utf-8")
        )
    ):
        raise AuthenticationError("invalid webhook secret")
    bot.process_update(payload)
    return {"ok": True}
