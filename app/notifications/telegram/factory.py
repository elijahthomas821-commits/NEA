"""Build the Telegram client from settings (None when no bot token is configured)."""

from __future__ import annotations

from app.config.settings import Settings
from app.notifications.telegram.client import TelegramClient


def build_telegram_client(settings: Settings) -> TelegramClient | None:
    if settings.telegram_bot_token is None:
        return None
    return TelegramClient(
        settings.telegram_bot_token.get_secret_value(), api_base=settings.telegram_api_base
    )
