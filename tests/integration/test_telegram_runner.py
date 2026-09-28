"""Update processing, polling, the webhook endpoint, and one full chat → alert round trip."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.api.ratelimit import InMemoryRateLimiter
from app.config.settings import Settings
from app.core.enums import AlertStatus
from app.main import create_app
from app.models import Alert, Listing
from app.notifications.telegram import runner as runner_module
from app.notifications.telegram import state
from app.notifications.telegram.client import TelegramClient, TelegramUnauthorizedError
from app.notifications.telegram.runner import (
    Poller,
    TelegramBot,
    build_bot,
    register_webhook,
    run_bot,
)
from app.workers.dispatch import InlineDispatcher, RecordingDispatcher
from app.workers.tasks.evaluate import run_evaluation
from app.workers.tasks.notify import deliver_alert
from tests.telegram_updates import callback, message

pytestmark = pytest.mark.integration

TOKEN = "123456789:AAH-runner-test-token-abcdefghijklmnopqrs"
BOT = f"https://api.telegram.org/bot{TOKEN}"
LINK = "https://www.vinted.co.uk/items/6660001111-stone-island-crewneck-sweatshirt"
SECRET = "webhook_secret_value_0123456789"


def ok(result=True):
    return httpx.Response(200, json={"ok": True, "result": result})


def sent():
    return ok({"message_id": 1})


@pytest.fixture
def tg_settings(settings):
    return settings.model_copy(update={"telegram_bot_token": SecretStr(TOKEN)})


@pytest.fixture
def client():
    with TelegramClient(TOKEN) as c:
        yield c


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def telegram_bot(tg_settings, test_db, client, dispatcher, sleeps):
    return TelegramBot(
        settings=tg_settings,
        database=test_db,
        client=client,
        dispatcher=dispatcher,
        sleep=sleeps.append,
    )


@pytest.fixture
def dispatcher():
    return RecordingDispatcher()


def texts(route):
    return [json.loads(call.request.content)["text"] for call in route.calls]


class TestProcessUpdate:
    @respx.mock
    def test_reply_after_commit(self, telegram_bot, dispatcher, db_session):
        send = respx.post(f"{BOT}/sendMessage").mock(return_value=sent())
        telegram_bot.process_update(message(f"{LINK} £45"))
        listing = db_session.scalar(select(Listing).where(Listing.external_id == "6660001111"))
        assert texts(send)[0].startswith(f"Checking #{listing.id}")
        assert dispatcher.calls == [
            ("evaluate_listing", {"listing_id": listing.id, "trigger": "ingest", "alert": "always"})
        ]

    @respx.mock
    def test_duplicate_update_is_handled_once(self, telegram_bot):
        send = respx.post(f"{BOT}/sendMessage").mock(return_value=sent())
        update = message("/help", update_id=424242)
        telegram_bot.process_update(update)
        telegram_bot.process_update(update)
        assert send.call_count == 1

    @respx.mock
    def test_invalid_payload_is_ignored(self, telegram_bot):
        send = respx.post(f"{BOT}/sendMessage").mock(return_value=sent())
        telegram_bot.process_update({"no": "update id"})
        assert not send.called

    @respx.mock
    def test_callback_side_effects(self, telegram_bot):
        answer = respx.post(f"{BOT}/answerCallbackQuery").mock(return_value=ok())
        telegram_bot.process_update(callback("zzz"))
        assert json.loads(answer.calls.last.request.content)["text"] == (
            "This button is no longer valid."
        )

    @respx.mock
    def test_short_flood_wait_is_retried(self, telegram_bot, sleeps):
        flood = httpx.Response(
            429,
            json={
                "ok": False,
                "error_code": 429,
                "description": "slow",
                "parameters": {"retry_after": 2},
            },
        )
        send = respx.post(f"{BOT}/sendMessage").mock(side_effect=[flood, sent()])
        telegram_bot.process_update(message("/help"))
        assert sleeps == [2]
        assert send.call_count == 2

    @respx.mock
    def test_long_flood_wait_and_rejections_are_dropped(self, telegram_bot, sleeps):
        flood = httpx.Response(
            429,
            json={
                "ok": False,
                "error_code": 429,
                "description": "slow",
                "parameters": {"retry_after": 600},
            },
        )
        respx.post(f"{BOT}/sendMessage").mock(return_value=flood)
        telegram_bot.process_update(message("/help"))  # no exception
        respx.post(f"{BOT}/sendMessage").mock(
            return_value=httpx.Response(
                403, json={"ok": False, "error_code": 403, "description": "Forbidden: blocked"}
            )
        )
        telegram_bot.process_update(message("/help"))
        respx.post(f"{BOT}/sendMessage").mock(side_effect=httpx.ConnectError("down"))
        telegram_bot.process_update(message("/help"))
        assert sleeps == [1]

    @respx.mock
    def test_queue_down_is_reported(self, telegram_bot):
        class Broken(RecordingDispatcher):
            def evaluate_listing(self, *args, **kwargs):
                raise ConnectionError("redis down")

        telegram_bot.dispatcher = Broken()
        send = respx.post(f"{BOT}/sendMessage").mock(return_value=sent())
        telegram_bot.process_update(message(f"{LINK} £45"))
        assert "couldn't queue the evaluation" in texts(send)[-1]


@respx.mock
def test_chat_to_alert_round_trip(tg_settings, test_db, client, db_session, recorder):
    """Paste a link → saved → evaluated → the alert arrives with BUY/PASS/REVIEW buttons."""
    from tests.integration.test_pipeline import seed_comps

    seed_comps(recorder)
    db_session.commit()
    send = respx.post(f"{BOT}/sendMessage").mock(return_value=sent())

    def notify(*, evaluation_id, alert):
        deliver_alert(
            evaluation_id, mode=alert, database=test_db, client=client, settings=tg_settings
        )

    bot = TelegramBot(
        settings=tg_settings,
        database=test_db,
        client=client,
        dispatcher=InlineDispatcher(evaluate=run_evaluation, notify=notify),
    )
    link = "https://www.vinted.co.uk/items/7770001111-stone-island-garment-dyed-crewneck-sweatshirt"
    bot.process_update(message(f"{link} £45 L very good navy"))
    checking, alert_text = texts(send)
    assert checking.startswith("Checking #")
    assert "Stone Island" in alert_text
    assert "Resale est." in alert_text
    assert "Estimates only — not guaranteed outcomes." in alert_text
    alert = db_session.scalar(select(Alert))
    assert alert.status == AlertStatus.SENT.value
    keyboard = json.loads(send.calls.last.request.content)["reply_markup"]["inline_keyboard"]
    assert keyboard[0][0]["callback_data"] == f"a:{alert.id}:b"
    assert keyboard[1][0]["url"] == "https://www.vinted.co.uk/items/7770001111"  # canonical


class TestPoller:
    @respx.mock
    def test_poll_once_stores_the_offset(self, telegram_bot, test_db):
        updates = respx.post(f"{BOT}/getUpdates").mock(
            side_effect=[
                ok([message("/help", update_id=501), message("/help", update_id=502)]),
                ok([]),
            ]
        )
        respx.post(f"{BOT}/sendMessage").mock(return_value=sent())
        poller = Poller(telegram_bot, sleep=lambda s: None)
        assert poller.poll_once() == 2
        with test_db.session_scope() as session:
            assert state.get_poll_offset(session) == 503
        assert poller.poll_once() == 0
        request = json.loads(updates.calls.last.request.content)
        assert request["offset"] == 503
        assert request["allowed_updates"] == ["message", "callback_query"]

    @respx.mock
    def test_poison_update_is_skipped_with_an_apology(self, telegram_bot, test_db, monkeypatch):
        respx.post(f"{BOT}/getUpdates").mock(return_value=ok([message("/help", update_id=601)]))
        send = respx.post(f"{BOT}/sendMessage").mock(return_value=sent())
        attempts = []

        def boom(*args, **kwargs):
            attempts.append(1)
            raise RuntimeError("bug")

        monkeypatch.setattr(telegram_bot.handler, "handle", boom)
        sleeps = []
        Poller(telegram_bot, sleep=sleeps.append).poll_once()
        assert len(attempts) == 3
        assert sleeps == [1, 2]
        assert "something went wrong" in texts(send)[-1]
        with test_db.session_scope() as session:
            assert state.get_poll_offset(session) == 602

    @respx.mock
    def test_database_outage_skips_nothing(self, telegram_bot, test_db, monkeypatch):
        respx.post(f"{BOT}/getUpdates").mock(return_value=ok([message("/help", update_id=701)]))

        def down(*args, **kwargs):
            raise OperationalError("select 1", {}, Exception("connection refused"))

        monkeypatch.setattr(telegram_bot.handler, "handle", down)
        with pytest.raises(OperationalError):
            Poller(telegram_bot).poll_once()
        with test_db.session_scope() as session:
            assert state.get_poll_offset(session) is None

    @respx.mock
    def test_stop_mid_batch_leaves_the_rest(self, telegram_bot, test_db):
        respx.post(f"{BOT}/getUpdates").mock(return_value=ok([message("/help", update_id=801)]))
        poller = Poller(telegram_bot)
        poller.stop()
        assert poller.poll_once() == 0
        with test_db.session_scope() as session:
            assert state.get_poll_offset(session) is None

    @respx.mock
    def test_run_backs_off_and_stops(self, telegram_bot):
        delete = respx.post(f"{BOT}/deleteWebhook").mock(return_value=ok())
        commands = respx.post(f"{BOT}/setMyCommands").mock(
            return_value=httpx.Response(
                400, json={"ok": False, "error_code": 400, "description": "bad"}
            )
        )
        sleeps: list[float] = []
        poller = Poller(telegram_bot, sleep=sleeps.append)
        calls = []

        def get_updates(request):
            calls.append(1)
            if len(calls) == 1:
                return httpx.Response(502, text="bad gateway")
            if len(calls) == 2:
                return httpx.Response(
                    429,
                    json={"ok": False, "error_code": 429, "description": "slow",
                          "parameters": {"retry_after": 3}},
                )  # fmt: skip
            if len(calls) == 3:
                return httpx.Response(
                    409, json={"ok": False, "error_code": 409, "description": "Conflict"}
                )
            poller.stop()
            return ok([])

        respx.post(f"{BOT}/getUpdates").mock(side_effect=get_updates)
        poller.run()
        assert delete.called
        assert commands.called  # failure to set commands is not fatal
        assert sleeps == [1.0, 3, 2.0]  # the backoff grows across consecutive failures

    @respx.mock
    def test_revoked_token_stops_the_bot(self, telegram_bot):
        respx.post(f"{BOT}/deleteWebhook").mock(return_value=ok())
        respx.post(f"{BOT}/setMyCommands").mock(return_value=ok())
        respx.post(f"{BOT}/getUpdates").mock(
            return_value=httpx.Response(
                401, json={"ok": False, "error_code": 401, "description": "Unauthorized"}
            )
        )
        with pytest.raises(TelegramUnauthorizedError):
            Poller(telegram_bot).run()


def webhook_settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "telegram_bot_token": SecretStr(TOKEN),
            "telegram_mode": "webhook",
            "telegram_webhook_url": "https://example.test/telegram/webhook",
            "telegram_webhook_secret": SecretStr(SECRET),
        }
    )


class TestWebhook:
    @pytest.fixture
    def hook_client(self, settings, test_db, client):
        cfg = webhook_settings(settings)
        bot = TelegramBot(
            settings=cfg, database=test_db, client=client, dispatcher=RecordingDispatcher()
        )
        app = create_app(
            cfg,
            database=test_db,  # type: ignore[arg-type]
            dispatcher=RecordingDispatcher(),
            rate_limiter=InMemoryRateLimiter(),
            telegram_bot=bot,
            configure_logs=False,
        )
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

    @respx.mock
    def test_secret_is_required(self, hook_client):
        send = respx.post(f"{BOT}/sendMessage").mock(return_value=sent())
        update = message("/help")
        assert hook_client.post("/telegram/webhook", json=update).status_code == 401
        wrong = {"X-Telegram-Bot-Api-Secret-Token": SECRET + "x"}
        assert hook_client.post("/telegram/webhook", json=update, headers=wrong).status_code == 401
        good = {"X-Telegram-Bot-Api-Secret-Token": SECRET}
        response = hook_client.post("/telegram/webhook", json=update, headers=good)
        assert (response.status_code, response.json()) == (200, {"ok": True})
        assert send.call_count == 1

    def test_not_served_in_polling_mode(self, client, settings):
        # The default test app (polling mode) has no webhook.
        app = create_app(
            settings.model_copy(update={"telegram_bot_token": SecretStr(TOKEN)}),
            dispatcher=RecordingDispatcher(),
            rate_limiter=InMemoryRateLimiter(),
            configure_logs=False,
        )
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/telegram/webhook",
                json=message("/help"),
                headers={"X-Telegram-Bot-Api-Secret-Token": SECRET},
            )
        assert response.status_code == 404

    def test_app_builds_the_bot_in_webhook_mode(self, settings, test_db):
        app = create_app(
            webhook_settings(settings),
            database=test_db,  # type: ignore[arg-type]
            dispatcher=RecordingDispatcher(),
            rate_limiter=InMemoryRateLimiter(),
            configure_logs=False,
        )
        assert isinstance(app.state.telegram_bot, TelegramBot)
        app.state.telegram_bot.client.close()


@respx.mock
def test_register_webhook(settings, client):
    hook = respx.post(f"{BOT}/setWebhook").mock(return_value=ok())
    respx.post(f"{BOT}/setMyCommands").mock(return_value=ok())
    register_webhook(client, webhook_settings(settings))
    body = json.loads(hook.calls.last.request.content)
    assert body == {
        "url": "https://example.test/telegram/webhook",
        "secret_token": SECRET,
        "allowed_updates": ["message", "callback_query"],
        "max_connections": 1,
    }
    with pytest.raises(ValueError, match="webhook mode needs"):
        register_webhook(client, settings)


class TestRunBot:
    def test_needs_a_token(self, settings):
        assert build_bot(settings) is None
        assert run_bot(settings) == 2

    @respx.mock
    def test_webhook_mode_registers_and_exits(self, settings, test_db):
        respx.post(f"{BOT}/setWebhook").mock(return_value=ok())
        respx.post(f"{BOT}/setMyCommands").mock(return_value=ok())
        assert run_bot(webhook_settings(settings)) == 0

    def test_polling_mode_installs_signal_handlers(self, settings, test_db, monkeypatch):
        handlers = {}
        monkeypatch.setattr(runner_module.signal, "signal", handlers.__setitem__)
        monkeypatch.setattr(Poller, "run", lambda self: None)
        cfg = settings.model_copy(
            update={"telegram_bot_token": SecretStr(TOKEN), "telegram_allowed_user_ids": []}
        )
        assert run_bot(cfg) == 0
        assert set(handlers) == {runner_module.signal.SIGTERM, runner_module.signal.SIGINT}

    def test_revoked_token_exit_code(self, settings, test_db, monkeypatch):
        def revoked(self):
            raise TelegramUnauthorizedError("Unauthorized")

        monkeypatch.setattr(runner_module.signal, "signal", lambda *a: None)
        monkeypatch.setattr(Poller, "run", revoked)
        cfg = settings.model_copy(update={"telegram_bot_token": SecretStr(TOKEN)})
        assert run_bot(cfg) == 3


class TestWebhookSettings:
    def test_secret_format(self):
        with pytest.raises(ValidationError, match="TELEGRAM_WEBHOOK_SECRET must be"):
            Settings(_env_file=None, telegram_webhook_secret="short")  # type: ignore[call-arg]
        with pytest.raises(ValidationError, match="TELEGRAM_WEBHOOK_SECRET must be"):
            Settings(_env_file=None, telegram_webhook_secret="has spaces in it!!")  # type: ignore[call-arg]
        Settings(_env_file=None, telegram_webhook_secret=SECRET)  # type: ignore[call-arg]

    def test_webhook_mode_requirements(self):
        with pytest.raises(ValidationError, match="https"):
            Settings(_env_file=None, telegram_mode="webhook")  # type: ignore[call-arg]
