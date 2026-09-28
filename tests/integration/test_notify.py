"""Alert delivery: idempotency, the re-alert policy, retries and failure handling."""

from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal

import httpx
import pytest
import respx
from pydantic import SecretStr
from sqlalchemy import select

from app.core.enums import AlertMode, AlertStatus, Decision
from app.models import Alert
from app.notifications.telegram.client import TelegramClient
from app.services.config_service import ConfigService
from app.services.ingestion import update_listing
from app.services.pipeline import EvaluationContext, evaluate_listing
from app.workers.tasks import notify
from app.workers.tasks.notify import (
    DeliveryResult,
    Outcome,
    deliver_alert,
    mark_alert_failed,
    requeue_pending_alerts,
    retry_countdown,
    send_alert_task,
)
from tests.factories import NOW
from tests.integration.test_pipeline import listing_for, seed_comps

pytestmark = pytest.mark.integration

TOKEN = "123456789:AAH-notify-test-token-abcdefghijklmnopqr"
SEND = f"https://api.telegram.org/bot{TOKEN}/sendMessage"


@pytest.fixture
def tg_settings(settings):
    return settings.model_copy(update={"telegram_bot_token": SecretStr(TOKEN)})


@pytest.fixture
def client():
    with TelegramClient(TOKEN) as c:
        yield c


def evaluate(db_session, tmp_path, listing):
    ctx = EvaluationContext(
        bundle=ConfigService(db_session).bundle(), ai=None, media_dir=tmp_path, now=NOW
    )
    evaluation = evaluate_listing(db_session, listing, ctx, trigger="ingest")
    db_session.commit()
    return evaluation


@pytest.fixture
def evaluation(db_session, tmp_path, recorder):
    seed_comps(recorder)
    return evaluate(db_session, tmp_path, listing_for(db_session))


def deliver(test_db, client, settings, evaluation_id, mode=AlertMode.ALWAYS):
    return deliver_alert(
        evaluation_id, mode=mode, database=test_db, client=client, settings=settings, now=NOW
    )


def alert_for(db_session, evaluation_id):
    db_session.expire_all()
    return db_session.scalar(select(Alert).where(Alert.evaluation_id == evaluation_id))


def sent(message_id=77):
    return httpx.Response(200, json={"ok": True, "result": {"message_id": message_id}})


@respx.mock
def test_sends_once(test_db, db_session, client, tg_settings, evaluation):
    route = respx.post(SEND).mock(return_value=sent())
    assert deliver(test_db, client, tg_settings, evaluation.id).outcome is Outcome.SENT
    assert deliver(test_db, client, tg_settings, evaluation.id).outcome is Outcome.ALREADY_DONE
    assert route.call_count == 1

    alert = alert_for(db_session, evaluation.id)
    assert alert.status == AlertStatus.SENT.value
    assert alert.external_message_id == 77
    assert alert.chat_id == 111
    assert alert.attempts == 1
    assert alert.priority == "review"
    body = json.loads(route.calls.last.request.content)
    assert body["chat_id"] == 111
    assert "Estimates only — not guaranteed outcomes." in body["text"]
    assert f"#{evaluation.listing_id}" in body["text"]
    buttons = body["reply_markup"]["inline_keyboard"][0]
    assert [b["callback_data"] for b in buttons] == [
        f"a:{alert.id}:b",
        f"a:{alert.id}:p",
        f"a:{alert.id}:r",
    ]


@respx.mock
def test_deals_mode_suppresses_rejections(test_db, db_session, client, tg_settings, tmp_path):
    route = respx.post(SEND).mock(return_value=sent())
    rejected = evaluate(db_session, tmp_path, listing_for(db_session))  # no comps at all
    assert rejected.decision == Decision.REJECTED.value
    result = deliver(test_db, client, tg_settings, rejected.id, AlertMode.DEALS)
    assert result.outcome is Outcome.SUPPRESSED
    assert result.detail == "not a deal"
    assert alert_for(db_session, rejected.id).status == AlertStatus.SUPPRESSED.value
    # A redelivered task does not change its mind.
    again = deliver(test_db, client, tg_settings, rejected.id, AlertMode.ALWAYS)
    assert again.outcome is Outcome.ALREADY_DONE
    assert not route.called


@respx.mock
def test_realert_policy_across_evaluations(
    test_db, db_session, client, tg_settings, tmp_path, recorder
):
    respx.post(SEND).mock(return_value=sent())
    seed_comps(recorder)
    listing = listing_for(db_session)
    first = evaluate(db_session, tmp_path, listing)
    assert deliver(test_db, client, tg_settings, first.id, AlertMode.DEALS).outcome is Outcome.SENT

    same = evaluate(db_session, tmp_path, listing)
    result = deliver(test_db, client, tg_settings, same.id, AlertMode.DEALS)
    assert result.outcome is Outcome.SUPPRESSED
    assert result.detail == "no material change since the last alert"

    # £45 → £40 clears both thresholds (£5 and 10%). (£38 would be below 35% of the £110
    # median: a "too good to be true" price that is rejected for counterfeit risk.)
    update_listing(db_session, listing.id, now=NOW, price=Decimal("40.00"))
    cheaper = evaluate(db_session, tmp_path, listing)
    result = deliver(test_db, client, tg_settings, cheaper.id, AlertMode.DEALS)
    assert result.outcome is Outcome.SENT


@respx.mock
def test_flood_control_then_success(test_db, db_session, client, tg_settings, evaluation):
    respx.post(SEND).mock(
        side_effect=[
            httpx.Response(
                429,
                json={
                    "ok": False,
                    "error_code": 429,
                    "description": "Too Many Requests",
                    "parameters": {"retry_after": 12},
                },
            ),
            sent(),
        ]
    )
    first = deliver(test_db, client, tg_settings, evaluation.id)
    assert (first.outcome, first.retry_after) == (Outcome.RETRY, 12)
    alert = alert_for(db_session, evaluation.id)
    assert (alert.status, alert.attempts) == (AlertStatus.PENDING.value, 1)
    assert "Too Many Requests" in alert.last_error

    assert deliver(test_db, client, tg_settings, evaluation.id).outcome is Outcome.SENT
    alert = alert_for(db_session, evaluation.id)
    assert (alert.status, alert.attempts, alert.last_error) == (AlertStatus.SENT.value, 2, None)


@respx.mock
def test_server_error_is_retried(test_db, client, tg_settings, evaluation):
    respx.post(SEND).mock(return_value=httpx.Response(502, text="bad gateway"))
    result = deliver(test_db, client, tg_settings, evaluation.id)
    assert (result.outcome, result.retry_after) == (Outcome.RETRY, None)


@respx.mock
def test_rejected_request_fails_without_retry(test_db, db_session, client, tg_settings, evaluation):
    respx.post(SEND).mock(
        return_value=httpx.Response(
            400, json={"ok": False, "error_code": 400, "description": "Bad Request: chat not found"}
        )
    )
    result = deliver(test_db, client, tg_settings, evaluation.id)
    assert result.outcome is Outcome.FAILED
    alert = alert_for(db_session, evaluation.id)
    assert alert.status == AlertStatus.FAILED.value
    assert TOKEN not in (alert.last_error or "")
    assert deliver(test_db, client, tg_settings, evaluation.id).outcome is Outcome.ALREADY_DONE


def test_not_configured_or_missing(test_db, db_session, client, settings, tg_settings, evaluation):
    assert deliver(test_db, None, tg_settings, evaluation.id).outcome is Outcome.SKIPPED
    no_chat = tg_settings.model_copy(update={"telegram_allowed_user_ids": []})
    assert deliver(test_db, client, no_chat, evaluation.id).outcome is Outcome.SKIPPED
    assert alert_for(db_session, evaluation.id) is None
    assert deliver(test_db, client, tg_settings, 987654321).outcome is Outcome.MISSING


@respx.mock
def test_explicit_alert_chat(test_db, client, tg_settings, evaluation):
    route = respx.post(SEND).mock(return_value=sent())
    settings = tg_settings.model_copy(update={"telegram_alert_chat_id": -100123})
    deliver(test_db, client, settings, evaluation.id)
    assert json.loads(route.calls.last.request.content)["chat_id"] == -100123


def test_mark_failed_and_requeue(test_db, db_session, client, tg_settings, evaluation):
    with respx.mock:
        respx.post(SEND).mock(return_value=httpx.Response(503, text="down"))
        deliver(test_db, client, tg_settings, evaluation.id)
    later = NOW.replace(year=NOW.year + 1)
    # Stale pending alerts are handed back; alerts pending for days are given up.
    assert requeue_pending_alerts(test_db, now=db_now(db_session) + timedelta(minutes=11)) == [
        evaluation.id
    ]
    assert requeue_pending_alerts(test_db, now=db_now(db_session) + timedelta(minutes=5)) == []
    assert requeue_pending_alerts(test_db, now=later) == []
    assert alert_for(db_session, evaluation.id).status == AlertStatus.FAILED.value

    mark_alert_failed(test_db, evaluation.id, "x")  # no pending row: nothing happens


def db_now(db_session):
    from sqlalchemy import func

    return db_session.scalar(select(func.now()))


def test_retry_countdown():
    assert retry_countdown(0, 12) == 13
    assert 10 <= retry_countdown(0, None) <= 15
    assert 600 <= retry_countdown(30, None) <= 605


class TestCeleryTask:
    def test_gives_up_after_max_retries(self, monkeypatch, test_db, db_session, evaluation):
        calls = []

        def fake_deliver(evaluation_id, **kwargs):
            calls.append(kwargs["mode"])
            with test_db.session_scope() as session:
                if (
                    session.scalar(select(Alert).where(Alert.evaluation_id == evaluation_id))
                    is None
                ):
                    session.add(
                        Alert(
                            evaluation_id=evaluation_id,
                            listing_id=evaluation.listing_id,
                            priority="review",
                            status="pending",
                        )
                    )
            return DeliveryResult(Outcome.RETRY)

        monkeypatch.setattr(notify, "deliver_alert", fake_deliver)
        result = send_alert_task.apply(kwargs={"evaluation_id": evaluation.id, "alert": "deals"})
        assert result.get() == "failed"
        assert len(calls) == send_alert_task.max_retries + 1
        assert calls[0] is AlertMode.DEALS
        assert alert_for(db_session, evaluation.id).status == AlertStatus.FAILED.value

    def test_returns_outcome(self, monkeypatch, test_db):
        monkeypatch.setattr(notify, "deliver_alert", lambda *a, **k: DeliveryResult(Outcome.SENT))
        assert send_alert_task.apply(kwargs={"evaluation_id": 1}).get() == "sent"

    def test_retry_pending_task_dispatches(self, monkeypatch, test_db):
        from app.workers.dispatch import RecordingDispatcher

        recorder = RecordingDispatcher()
        monkeypatch.setattr(notify, "requeue_pending_alerts", lambda db, now: [5, 6])
        monkeypatch.setattr(notify, "CeleryDispatcher", lambda: recorder)
        assert notify.retry_pending_alerts_task.apply().get() == 2
        assert recorder.calls == [
            ("send_alert", {"evaluation_id": 5, "alert": "always"}),
            ("send_alert", {"evaluation_id": 6, "alert": "always"}),
        ]
