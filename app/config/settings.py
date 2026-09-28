"""Environment settings (secrets and deployment parameters).

Business rules (fees, thresholds, multipliers) are *not* here: they are versioned configuration
stored in the database (see :mod:`app.config.schemas`). Secrets never go in the database.
"""

from __future__ import annotations

from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.redaction import register_secret


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: Literal["dev", "test", "prod"] = "dev"
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"

    database_url: SecretStr = SecretStr("postgresql+psycopg://resale:resale@localhost:5432/resale")
    database_pool_size: int = Field(default=5, ge=1, le=50)
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # Base currency of the operator's business. Listings in other currencies are only
    # evaluated when an FX rate is on record.
    base_currency: str = "GBP"
    display_timezone: str = "Europe/London"
    default_marketplace: str = "vinted"

    # Storage for uploaded listing photos (Telegram / API uploads). Nothing is fetched from
    # marketplace URLs.
    media_dir: Path = Path("./media")
    max_image_bytes: int = Field(default=8 * 1024 * 1024, ge=1024)
    max_images_per_listing: int = Field(default=12, ge=1, le=40)
    max_upload_bytes: int = Field(default=5 * 1024 * 1024, ge=1024)
    max_request_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)

    # API
    api_rate_limit_per_minute: int = Field(default=120, ge=1)
    api_docs_enabled: bool = True

    # Telegram
    telegram_bot_token: SecretStr | None = None
    telegram_allowed_user_ids: Annotated[list[int], NoDecode] = Field(default_factory=list)
    telegram_alert_chat_id: int | None = None
    telegram_mode: Literal["polling", "webhook"] = "polling"
    telegram_webhook_url: str | None = None
    telegram_webhook_secret: SecretStr | None = None
    telegram_api_base: str = "https://api.telegram.org"
    telegram_poll_timeout_seconds: int = Field(default=30, ge=1, le=50)

    # AI (optional). Disabled unless an API key is present and ai_enabled is true.
    ai_enabled: bool = True
    anthropic_api_key: SecretStr | None = None
    ai_model: str = "claude-sonnet-5"
    ai_timeout_seconds: float = Field(default=45.0, gt=0, le=300)
    ai_daily_budget_usd: Decimal = Field(default=Decimal("1.00"), ge=0)
    ai_monthly_budget_usd: Decimal = Field(default=Decimal("10.00"), ge=0)
    ai_max_images: int = Field(default=6, ge=1, le=20)

    @field_validator("telegram_allowed_user_ids", mode="before")
    @classmethod
    def _split_ids(cls, value: object) -> object:
        if isinstance(value, str):
            parts = [p.strip() for p in value.replace(";", ",").split(",")]
            return [int(p) for p in parts if p]
        if isinstance(value, int):
            return [value]
        return value

    @field_validator("base_currency")
    @classmethod
    def _upper_currency(cls, value: str) -> str:
        value = value.strip().upper()
        if len(value) != 3 or not value.isalpha():
            raise ValueError("base_currency must be a 3-letter ISO code")
        return value

    @model_validator(mode="after")
    def _check_webhook(self) -> Settings:
        if self.telegram_mode == "webhook":
            if not self.telegram_webhook_url or not self.telegram_webhook_url.startswith(
                "https://"
            ):
                raise ValueError("webhook mode requires an https:// TELEGRAM_WEBHOOK_URL")
            if self.telegram_webhook_secret is None:
                raise ValueError("webhook mode requires TELEGRAM_WEBHOOK_SECRET")
        return self

    @property
    def ai_active(self) -> bool:
        return self.ai_enabled and self.anthropic_api_key is not None

    @property
    def telegram_active(self) -> bool:
        return self.telegram_bot_token is not None

    @property
    def alert_chat_id(self) -> int | None:
        """Where alerts go: an explicit chat, else the first allowed user's private chat."""
        if self.telegram_alert_chat_id is not None:
            return self.telegram_alert_chat_id
        return self.telegram_allowed_user_ids[0] if self.telegram_allowed_user_ids else None

    def register_secrets(self) -> None:
        """Make every configured secret known to the log redactor."""
        for secret in (
            self.telegram_bot_token,
            self.telegram_webhook_secret,
            self.anthropic_api_key,
        ):
            if secret is not None:
                register_secret(secret.get_secret_value())
        for url in (self.database_url, self.redis_url):
            password = _password_from_url(url.get_secret_value())
            if password:
                register_secret(password)


def _password_from_url(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).password
    except ValueError:
        return None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.register_secrets()
    return settings
