"""The whole loop, as you would use it:

market data → paste a listing in Telegram → evaluated → alert → photos → re-evaluated (AI photo
checklist) → BUY → what you paid → received → listed → sold → the prediction is scored, your
sale becomes market data, and analytics add up.

Real PostgreSQL; Telegram's HTTP API mocked with respx; the AI provider is a fake.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal

import httpx
import pytest
import respx
from pydantic import SecretStr
from sqlalchemy import func, select

from app.core.enums import AlertStatus
from app.core.time import utcnow
from app.models import Alert, InventoryItem, Listing, MarketSale, PredictionResult
from app.notifications.telegram.client import TelegramClient
from app.notifications.telegram.runner import TelegramBot
from app.services import pipeline
from app.services.ai.fake import FakeProvider
from app.services.ai.schemas import AIChecklistItem, AIListingAnalysis
from app.services.ai.service import AIService
from app.workers.dispatch import InlineDispatcher
from app.workers.tasks.evaluate import run_evaluation
from app.workers.tasks.notify import Outcome, deliver_alert
from tests.factories import image_bytes
from tests.telegram_updates import callback, message

pytestmark = [pytest.mark.integration, pytest.mark.e2e]

TOKEN = "123456789:AAH-e2e-test-token-abcdefghijklmnopqrstuv"
BOT = f"https://api.telegram.org/bot{TOKEN}"
FILES = f"https://api.telegram.org/file/bot{TOKEN}"
LINK = "https://www.vinted.co.uk/items/8880001111-stone-island-garment-dyed-crewneck-sweatshirt"


def fake_ai(test_db) -> AIService:
    checklist = [
        AIChecklistItem(brand="stone-island", code=code, result="observed", note="clear")
        for code in ("compass_badge", "badge_back", "authenticity_label", "care_labels")
    ]
    provider = FakeProvider(
        lambda request: AIListingAnalysis(
            brand="stone-island",
            category="sweatshirts",
            identification_confidence=Decimal("0.9"),
            photo_brand="stone-island",
            photo_brand_confidence=Decimal("0.9"),
            checklist=checklist,
            photo_quality="good",
        )
    )
    return AIService(
        provider,
        session_scope=test_db.session_scope,
        daily_budget_usd=Decimal(1),
        monthly_budget_usd=Decimal(10),
    )


class Chat:
    """Everything Telegram receives from the bot and the notifier."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.next_id = 900

    def send(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.sent.append(body)
        self.next_id += 1
        return httpx.Response(200, json={"ok": True, "result": {"message_id": self.next_id}})

    def texts(self) -> list[str]:
        return [m["text"] for m in self.sent]

    def last_alert(self) -> dict:
        return next(m for m in reversed(self.sent) if "Estimates only" in m["text"])


@pytest.fixture
def world(settings, test_db, monkeypatch):
    tg_settings = settings.model_copy(update={"telegram_bot_token": SecretStr(TOKEN)})
    client = TelegramClient(TOKEN)
    ai = fake_ai(test_db)
    monkeypatch.setattr(pipeline, "build_ai_service", lambda *args, **kwargs: ai)
    monkeypatch.setattr(pipeline, "get_settings", lambda: tg_settings)

    def notify(*, evaluation_id, alert):
        result = deliver_alert(
            evaluation_id, mode=alert, database=test_db, client=client, settings=tg_settings
        )
        if result.outcome is Outcome.RETRY:  # what the Celery task's retry does
            deliver_alert(
                evaluation_id, mode=alert, database=test_db, client=client, settings=tg_settings
            )

    bot = TelegramBot(
        settings=tg_settings,
        database=test_db,
        client=client,
        dispatcher=InlineDispatcher(evaluate=run_evaluation, notify=notify),
        sleep=lambda _s: None,
    )
    yield bot
    client.close()


@respx.mock
def test_from_listing_to_analytics(world, auth_client, db_session, operator):
    chat = Chat()
    respx.post(f"{BOT}/sendMessage").mock(side_effect=chat.send)
    respx.post(f"{BOT}/answerCallbackQuery").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": True})
    )
    respx.post(f"{BOT}/editMessageReplyMarkup").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": True})
    )
    photos = {f"photo{i}": image_bytes(seed=60 + i) for i in range(4)}
    respx.post(f"{BOT}/getFile").mock(
        side_effect=lambda r: httpx.Response(
            200,
            json={
                "ok": True,
                "result": {"file_path": f"photos/{json.loads(r.content)['file_id']}.jpg"},
            },
        )
    )
    respx.get(url__regex=rf"^{re.escape(FILES)}/photos/(?P<name>\w+)\.jpg$").mock(
        side_effect=lambda r, name: httpx.Response(200, content=photos[name])
    )

    # 1. Market data you researched: ten sold comparables, through the API.
    for i in range(10):
        response = auth_client.post(
            "/market/sales",
            json={
                "brand": "Stone Island",
                "category": "sweatshirts",
                "title": "Stone Island garment dyed crewneck sweatshirt navy",
                "size": "L",
                "condition": "very good",
                "colour": "navy",
                "sale_price": str(Decimal(110) + i % 3 - 1),
                "listed_at": f"2026-09-{i + 1:02d}T10:00:00Z",
                "sold_at": f"2026-09-{i + 10:02d}T10:00:00Z",
                "source_ref": f"e2e:{i}",
            },
        )
        assert response.status_code == 201, response.json()

    # 2. Paste the listing: saved, evaluated, and the result arrives as an alert.
    world.process_update(message(f"{LINK} £45 L very good navy"))
    listing = db_session.scalar(select(Listing).where(Listing.external_id == "8880001111"))
    assert chat.texts()[0].startswith(f"Checking #{listing.id}")
    first_alert = chat.last_alert()
    assert "Resale est. £1" in first_alert["text"]
    assert "Before buying" in first_alert["text"]  # no photos yet: evidence is asked for

    # 3. Photos of the badge and labels, then "Evaluate now": the AI checks the photos.
    for i in range(4):
        world.process_update(message(photo=f"photo{i}", media_group_id="album1"))
    assert (
        len(db_session.scalars(select(Listing).where(Listing.id == listing.id)).one().images) == 4
    )
    world.process_update(callback(f"e:{listing.id}"))
    second_alert = chat.last_alert()
    assert second_alert is not first_alert
    alerts = list(db_session.scalars(select(Alert).order_by(Alert.id)))
    assert [a.status for a in alerts] == [AlertStatus.SENT.value] * 2
    latest = alerts[-1]
    assert latest.evaluation.ai_used
    assert latest.evaluation.decision in ("high_priority", "normal")

    # 4. BUY (records intent only), then what you actually paid.
    world.process_update(callback(f"a:{latest.id}:b", message_id=latest.external_message_id))
    assert "Nothing has been bought" in chat.texts()[-1]
    world.process_update(message("45"))
    assert "= <b>£50.94</b>" in chat.texts()[-1]
    world.process_update(callback("f:ok"))
    item = db_session.scalar(select(InventoryItem).where(InventoryItem.listing_id == listing.id))
    assert item is not None
    assert f"It is item {item.id} in your stock" in chat.texts()[-1]

    # 5. It arrives, you list it and sell it.
    world.process_update(message(f"/received {item.id} very good"))
    world.process_update(message(f"/listed {item.id} £115"))
    world.process_update(message(f"/sale {item.id} £108"))
    assert "profit <b>£56.56</b>" in chat.texts()[-1]  # 108 − 0.50 packaging − 50.94

    # 6. The loop closes: prediction scored, your sale is market data, analytics add up.
    prediction = db_session.scalar(
        select(PredictionResult).where(PredictionResult.inventory_item_id == item.id)
    )
    assert prediction.actual_sale_price == Decimal("108.00")
    assert prediction.actual_profit == Decimal("56.56")
    assert (
        db_session.scalar(select(func.count(MarketSale.id)).where(MarketSale.source == "own_sale"))
        == 1
    )

    today = utcnow().date().isoformat()
    summary = auth_client.get("/analytics/summary", params={"from": today, "to": today}).json()
    assert summary["summary"]["sales"]["items_sold"] == 1
    assert summary["summary"]["sales"]["realised_profit"] == "56.56"
    assert summary["stock"]["items"] == 0
    accuracy = auth_client.get("/analytics/predictions").json()
    assert accuracy["overall"]["resolved"] == 1
    funnel = auth_client.get("/analytics/funnel").json()
    assert funnel["alerts_sent"] == 2
    assert funnel["your_decisions"] == {"buy": 1}
    assert (funnel["purchases_from_alerts"], funnel["buy_rate"]) == (1, "0.5000")
    assert funnel["ai_requests"] >= 1


@respx.mock
def test_telegram_failures_never_duplicate_alerts(world, db_session, recorder):
    """Flood control on the first attempt, then a redelivered update: one alert, sent once."""
    from tests.integration.test_pipeline import seed_comps

    seed_comps(recorder)
    db_session.commit()
    flood = httpx.Response(
        429,
        json={"ok": False, "error_code": 429, "description": "Too Many Requests",
              "parameters": {"retry_after": 1}},
    )  # fmt: skip
    chat = Chat()
    calls = {"n": 0}

    def send(request):
        calls["n"] += 1
        body = json.loads(request.content)
        if "Estimates only" in body["text"] and calls.setdefault("flooded", 0) == 0:
            calls["flooded"] = 1
            return flood
        return chat.send(request)

    respx.post(f"{BOT}/sendMessage").mock(side_effect=send)
    update = message(f"{LINK} £45", update_id=777_001)
    world.process_update(update)
    world.process_update(update)  # Telegram re-delivers the same update
    alerts = list(db_session.scalars(select(Alert)))
    assert len(alerts) == 1
    assert (alerts[0].status, alerts[0].attempts) == (AlertStatus.SENT.value, 2)
    assert sum("Estimates only" in t for t in chat.texts()) == 1
