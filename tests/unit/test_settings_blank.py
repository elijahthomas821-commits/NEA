"""Settings left empty in .env count as not set."""

from app.config.settings import Settings


def test_blank_values_are_unset():
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        telegram_bot_token="",
        anthropic_api_key="   ",
        telegram_alert_chat_id="",
        telegram_webhook_secret="",
    )
    assert settings.telegram_bot_token is None
    assert settings.anthropic_api_key is None
    assert settings.telegram_alert_chat_id is None
    assert not settings.telegram_active
    assert not settings.ai_active


def test_token_whitespace_is_trimmed():
    settings = Settings(_env_file=None, telegram_bot_token=" 123:abc \n")  # type: ignore[call-arg]
    assert settings.telegram_bot_token.get_secret_value() == "123:abc"
