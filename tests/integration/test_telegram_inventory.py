"""Stock and sales in the chat: /stock /item /received /listed /sale /shipped /done /writeoff
/stats."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.models import Brand, Category, InventoryItem, MarketSale, PredictionResult
from app.services.audit import Actor
from app.services.purchases import PurchaseCosts, PurchaseItem, record_purchase_items
from tests.integration.test_notify import evaluate
from tests.integration.test_pipeline import listing_for, seed_comps
from tests.telegram_updates import BOT_NOW as NOW
from tests.telegram_updates import callback, last, message

pytestmark = pytest.mark.integration

D = Decimal


@pytest.fixture
def stock(db_session, bot):
    bot.send(message("/help"))  # first contact creates the operator
    brand = db_session.scalar(select(Brand.id).where(Brand.slug == "stone-island"))
    category = db_session.scalar(select(Category.id).where(Category.slug == "sweatshirts"))
    _, items = record_purchase_items(
        db_session,
        items=[
            PurchaseItem(title="Stone Island crewneck <navy>", brand_id=brand, category_id=category,
                         expected_resale_price=D("110")),
            PurchaseItem(title="Mystery jacket", expected_resale_price=D("40")),
        ],
        costs=PurchaseCosts(D("60.00")),
        currency="GBP", marketplace="vinted", purchased_at=NOW - timedelta(days=10),
        actor=Actor.system("test"), allocation="equal",
    )  # fmt: skip
    db_session.commit()
    return items


def test_stock_and_item(bot, stock):
    text = last(bot.send(message("/stock")))
    assert "<b>Stock:</b> 2 items, £60.00 tied up" in text
    assert "Expected resale value £150.00 (estimate)" in text
    assert f"item {stock[0].id} Stone Island crewneck &lt;navy&gt; — ordered · 10 days" in text
    detail = last(bot.send(message(f"/item i{stock[0].id}")))
    assert "Cost £30.00 (purchase share £30.00)" in detail
    assert "Held 10 days" in detail
    assert "Expected resale £110.00" in detail


def test_empty_stock(bot):
    assert "No stock" in last(bot.send(message("/stock")))


def test_lifecycle_and_sale(bot, db_session, stock):
    item = stock[0]
    assert last(bot.send(message(f"/received {item.id} very good"))).endswith("received.")
    assert "listed at £99.00" in last(bot.send(message(f"/listed {item.id} £99")))
    out = bot.send(message(f"/sale {item.id} £95"))
    text = last(out)
    assert f"Sold item {item.id}" in text
    assert "Net £94.50 after selling costs · profit <b>£64.50</b>" in text
    assert "Added to your market data." in text
    sale = db_session.scalar(select(MarketSale).where(MarketSale.inventory_item_id == item.id))
    assert sale.source == "own_sale"
    assert "shipped" in last(bot.send(message(f"/shipped {item.id}")))
    assert "completed" in last(bot.send(message(f"/done {item.id}")))
    detail = last(bot.send(message(f"/item {item.id}")))
    assert "Sold £95.00 on" in detail
    assert "profit £64.50" in detail
    db_session.expire_all()
    assert db_session.get(InventoryItem, item.id).status == "completed"


def test_write_off_and_errors(bot, stock):
    item = stock[1]
    assert "a loss of £30.00" in last(bot.send(message(f"/writeoff {item.id}")))
    assert "can't become" in last(bot.send(message(f"/received {item.id}")))
    assert "can't be sold" in last(bot.send(message(f"/sale {item.id} £10")))
    assert "Usage: /sale 7 £95" in last(bot.send(message(f"/sale {stock[0].id}")))
    assert "Usage: /item 7" in last(bot.send(message("/item abc")))
    assert "not found" in last(bot.send(message("/item 999999")))
    assert "unknown condition" in last(bot.send(message(f"/received {stock[0].id} mint")))


def test_stats(bot, stock):
    bot.send(message(f"/received {stock[0].id}"))
    bot.send(message(f"/sale {stock[0].id} £80"))
    bot.send(message(f"/writeoff {stock[1].id}"))
    text = last(bot.send(message("/stats")))
    assert "Bought 2 for £60.00" in text
    assert "Sold 1 for £80.00 · profit £49.50 · ROI 165%" in text
    assert "Written off 1 (£30.00), returned 0" in text
    assert "Net result £19.50" in text
    assert "Stock: 0 items, £0.00 tied up" in text


def test_buy_in_chat_to_sale(bot, db_session, tmp_path, recorder):
    """BUY → price paid → confirm → received → listed → sold: the prediction is scored."""
    from app.models import Alert

    bot.send(message("/help"))
    seed_comps(recorder)
    listing = listing_for(db_session)
    evaluation = evaluate(db_session, tmp_path, listing)
    alert = Alert(evaluation_id=evaluation.id, listing_id=listing.id, priority="review",
                  status="sent", chat_id=111, external_message_id=500)  # fmt: skip
    db_session.add(alert)
    db_session.commit()

    bot.send(callback(f"a:{alert.id}:b"))
    bot.send(message("45"))
    confirmed = last(bot.send(callback("f:ok")))
    item = db_session.scalar(select(InventoryItem).where(InventoryItem.listing_id == listing.id))
    assert f"It is item {item.id} in your stock (ordered)" in confirmed
    bot.send(message(f"/received {item.id}"))
    bot.send(message(f"/listed {item.id} £115"))
    text = last(bot.send(message(f"/sale {item.id} £108")))
    assert "Predicted £" in text
    prediction = db_session.scalar(
        select(PredictionResult).where(PredictionResult.inventory_item_id == item.id)
    )
    assert prediction.actual_sale_price == D("108.00")
    assert prediction.resolved_at is not None
