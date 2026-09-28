"""Build the AI service from settings (disabled when no key is configured)."""

from __future__ import annotations

from app.config.settings import Settings
from app.database.session import Database
from app.services.ai.anthropic_provider import AnthropicProvider
from app.services.ai.provider import AIProvider
from app.services.ai.service import AIService


def build_ai_service(settings: Settings, database: Database) -> AIService:
    provider: AIProvider | None = None
    if settings.ai_active and settings.anthropic_api_key is not None:
        provider = AnthropicProvider(
            api_key=settings.anthropic_api_key.get_secret_value(),
            model=settings.ai_model,
            timeout_seconds=settings.ai_timeout_seconds,
            effort=settings.ai_effort,
            refusal_fallbacks=settings.ai_refusal_fallbacks,
        )
    return AIService(
        provider,
        session_scope=database.session_scope,
        daily_budget_usd=settings.ai_daily_budget_usd,
        monthly_budget_usd=settings.ai_monthly_budget_usd,
    )
