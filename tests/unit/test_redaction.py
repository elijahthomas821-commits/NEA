import json
import logging

import pytest

from app.core.logging import configure_logging, get_logger
from app.core.redaction import (
    clear_registered_secrets,
    redact_text,
    redact_value,
    register_secret,
    safe_error_summary,
)

BOT_TOKEN = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_registered_secrets()
    yield
    clear_registered_secrets()


class TestPatterns:
    def test_telegram_token_in_bot_api_url(self):
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        out = redact_text(f"HTTP Request: POST {url} 200")
        assert BOT_TOKEN not in out
        assert "sendMessage" in out

    def test_anthropic_key(self):
        assert "abcdef123456" not in redact_text("key sk-ant-api03-abcdef123456XYZ")

    def test_own_api_key(self):
        assert "SECRETPART" not in redact_text("rsk_SECRETPARTSECRETPART1234")

    def test_bearer(self):
        out = redact_text("Authorization: Bearer abcdefghijklmnop")
        assert "abcdefghijklmnop" not in out
        assert "Bearer ***" in out

    def test_url_credentials(self):
        out = redact_text("postgresql+psycopg://resale:hunter22@db:5432/resale")
        assert "hunter22" not in out
        assert "resale:***@db" in out

    def test_query_param(self):
        out = redact_text("https://x.test/cb?token=abc123&x=1")
        assert "abc123" not in out
        assert "x=1" in out

    def test_registered_secret(self):
        register_secret("my-very-secret-value")
        assert redact_text("oops my-very-secret-value leaked") == "oops *** leaked"

    def test_short_secrets_not_registered(self):
        register_secret("abc")
        assert redact_text("abc") == "abc"


class TestStructured:
    def test_sensitive_keys(self):
        data = {"password": "p4ss", "api_key": "k", "nested": {"authorization": "Bearer x"}}
        out = redact_value(data)
        assert out["password"] == "***"
        assert out["api_key"] == "***"
        assert out["nested"]["authorization"] == "***"

    def test_token_counts_are_not_redacted(self):
        out = redact_value({"input_tokens": 120, "output_tokens": 55})
        assert out == {"input_tokens": 120, "output_tokens": 55}

    def test_lists_and_tuples(self):
        out = redact_value([f"bot{BOT_TOKEN}", ("sk-ant-xxxxxxxxxxxx",)])
        assert BOT_TOKEN not in json.dumps(out)
        assert "xxxxxxxxxxxx" not in json.dumps(out)

    def test_error_summary(self):
        exc = RuntimeError(f"failed calling https://api.telegram.org/bot{BOT_TOKEN}/getMe")
        summary = safe_error_summary(exc)
        assert BOT_TOKEN not in summary
        assert summary.startswith("RuntimeError:")


def test_logging_pipeline_redacts_stdlib_and_structlog(capsys):
    configure_logging("INFO", "json")
    register_secret("super-secret-db-pass")
    logging.getLogger("httpx").warning(
        "HTTP Request: POST https://api.telegram.org/bot%s/sendMessage", BOT_TOKEN
    )
    get_logger("test").info("connecting", dsn="postgres://u:super-secret-db-pass@h/db")
    try:
        raise ValueError(f"token {BOT_TOKEN}")
    except ValueError:
        get_logger("test").exception("boom")
    output = capsys.readouterr().out
    assert BOT_TOKEN not in output
    assert "super-secret-db-pass" not in output
    assert "sendMessage" in output
    for line in output.strip().splitlines():
        json.loads(line)  # every line is valid JSON
