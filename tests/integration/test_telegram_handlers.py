"""The chat interface: access control, listing intake, commands, photos and decisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.enums import ListingStatus, PriceType, SaleSource
from app.models import (
    Alert,
    AuditLog,
    Brand,
    Category,
    InventoryItem,
    Listing,
    ListingImage,
    MarketSale,
    PredictionResult,
    Purchase,
    User,
)
from app.notifications.telegram.handlers import BotHandler, EvaluationRequest, Outbox
from app.notifications.telegram.types import TgUpdate
from app.services.users import create_user
from tests.factories import image_bytes
from tests.integration.test_notify import evaluate
from tests.integration.test_pipeline import listing_for, seed_comps
from tests.telegram_updates import FakeFiles, callback, message

pytestmark = pytest.mark.integration

NOW = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)
LINK = "https://www.vinted.co.uk/items/5550001111-stone-island-crewneck-sweatshirt"


@dataclass
class Harness:
    handler: BotHandler
    test_db: object
    db_session: Session

    def send(self, update: dict) -> Outbox:
        outbox = Outbox()
        with self.test_db.session_scope() as session:  # type: ignore[attr-defined]
            self.handler.handle(session, TgUpdate.model_validate(update), outbox)
        self.db_session.expire_all()
        return outbox


@pytest.fixture
def files():
    return FakeFiles({f"p{i}": image_bytes(seed=i) for i in range(1, 5)})


@pytest.fixture
def bot(settings, test_db, db_session, files):
    return Harness(BotHandler(settings, files, clock=lambda: NOW), test_db, db_session)


def last(outbox: Outbox) -> str:
    assert outbox.messages, "no reply"
    return outbox.messages[-1].text


def listing_by_ref(db_session, external_id="5550001111") -> Listing:
    listing = db_session.scalar(select(Listing).where(Listing.external_id == external_id))
    assert listing is not None
    return listing


def operator(db_session) -> User:
    user = db_session.scalar(select(User).where(User.telegram_user_id == 111))
    assert user is not None
    return user


# --------------------------------------------------------------------------- access


class TestAccess:
    def test_stranger_start_learns_their_id(self, bot, db_session):
        out = bot.send(message("/start", user_id=999))
        assert "<code>999</code>" in last(out)
        assert db_session.scalar(select(User).where(User.telegram_user_id == 999)) is None

    @pytest.mark.parametrize(
        "update",
        [
            message("hello", user_id=999),
            message(f"{LINK} £45", user_id=999),
            message("/start", user_id=999, chat_id=-1001, chat_type="group"),
        ],
    )
    def test_stranger_is_ignored(self, bot, db_session, update):
        out = bot.send(update)
        assert out.messages == []
        assert out.evaluations == []
        assert db_session.scalar(select(func.count(Listing.id))) == 0

    def test_stranger_button(self, bot):
        out = bot.send(callback("a:1:b", user_id=999))
        assert [a.text for a in out.answers] == ["Not authorised."]
        assert out.messages == []

    def test_disabled_user(self, bot, db_session):
        user = create_user(db_session, "op", telegram_user_id=111)
        user.is_active = False
        db_session.commit()
        assert bot.send(message(f"{LINK} £45")).evaluations == []

    def test_bots_are_ignored(self, bot):
        update = message("/help")
        update["message"]["from"]["is_bot"] = True
        assert bot.send(update).messages == []

    def test_first_contact_creates_the_operator(self, bot, db_session):
        bot.send(message("/help"))
        user = operator(db_session)
        assert user.username == "user111"
        assert user.last_seen_at == NOW


# --------------------------------------------------------------------------- intake


class TestQuickAdd:
    def test_link_and_price(self, bot, db_session):
        out = bot.send(message(f"Check out this on Vinted: {LINK} £45"))
        listing = listing_by_ref(db_session)
        assert (listing.source, listing.price, listing.currency) == ("telegram", Decimal(45), "GBP")
        assert listing.submitted_by_user_id == operator(db_session).id
        assert out.evaluations == [EvaluationRequest(listing.id, "ingest")]
        assert last(out).startswith(f"Checking #{listing.id} stone island crewneck sweatshirt")

    def test_missing_price_is_asked_for(self, bot, db_session):
        out = bot.send(message(LINK))
        assert "What is the asking price?" in last(out)
        assert out.evaluations == []
        assert "Send just the price" in last(bot.send(message("cheap")))
        out = bot.send(message("45"))
        listing = listing_by_ref(db_session)
        assert listing.price == Decimal(45)
        assert out.evaluations == [EvaluationRequest(listing.id, "ingest")]

    def test_unchanged_resubmission(self, bot):
        bot.send(message(f"{LINK} £45"))
        out = bot.send(message(f"{LINK} £45"))
        assert "nothing changed" in last(out)
        assert out.evaluations == []

    def test_price_change_by_resubmission(self, bot, db_session):
        bot.send(message(f"{LINK} £45"))
        out = bot.send(message(f"{LINK} £40"))
        listing = listing_by_ref(db_session)
        assert out.evaluations == [EvaluationRequest(listing.id, "manual")]

    def test_text_with_a_price_but_no_link(self, bot, db_session):
        out = bot.send(message("Stone Island crewneck L £45"))
        listing = db_session.scalar(select(Listing))
        assert listing.title == "Stone Island crewneck L"
        assert out.evaluations == [EvaluationRequest(listing.id, "ingest")]

    def test_chatter_gets_a_hint(self, bot):
        assert "Send me a Vinted link" in last(bot.send(message("hello")))

    def test_non_text_message(self, bot):
        assert "I can read text and photos" in last(bot.send(message(None)))

    def test_link_replaces_an_open_question(self, bot, db_session):
        bot.send(message("/comp"))
        out = bot.send(message(f"{LINK} £45"))
        assert out.evaluations
        assert "Send me a Vinted link" in last(bot.send(message("hello")))  # comp flow ended


class TestGuidedAdd:
    def test_step_by_step(self, bot, db_session, files):
        assert "Send the Vinted link" in last(bot.send(message("/add")))
        assert "asking price" in last(bot.send(message(LINK)))
        out = bot.send(message("£45"))
        assert last(out) == "Brand? (e.g. Stone Island)"
        assert out.messages[-1].keyboard is not None
        assert last(bot.send(message("Stone Island"))).startswith("Size?")
        out = bot.send(callback("f:skip"))
        assert last(out) == "Condition?"
        assert out.edits
        assert out.edits[0].keyboard is None  # the answered question's buttons go
        assert "Send photos now" in last(bot.send(callback("f:very_good")))
        out = bot.send(message(photo="p1"))
        assert "Evaluate now" in last(out)
        assert "Send photos, or tap Evaluate" in last(bot.send(message("what now?")))
        out = bot.send(message("done"))
        listing = listing_by_ref(db_session)
        assert out.evaluations == [EvaluationRequest(listing.id, "ingest")]
        assert (listing.raw_brand, listing.raw_size, listing.raw_condition) == (
            "Stone Island",
            None,
            "Very good",
        )
        assert len(listing.images) == 1

    def test_link_with_price_as_argument(self, bot):
        assert last(bot.send(message(f"/add {LINK} £45"))) == "Brand? (e.g. Stone Island)"

    def test_condition_must_be_recognised(self, bot):
        bot.send(message(f"/add {LINK} £45"))
        bot.send(callback("f:skip"))
        bot.send(callback("f:skip"))
        assert "Pick a condition" in last(bot.send(message("mint-ish")))
        assert "Send photos now" in last(bot.send(message("good")))

    def test_cancel_button_and_command(self, bot):
        bot.send(message(f"/add {LINK} £45"))
        assert last(bot.send(callback("f:cancel"))) == "Cancelled."
        assert last(bot.send(message("/cancel"))) == "Nothing to cancel."
        bot.send(message("/add"))
        assert last(bot.send(message("/cancel"))) == "Cancelled."

    def test_photo_before_the_link_is_not_guessed(self, bot, db_session):
        bot.send(message(f"{LINK} £45"))  # an earlier listing is in focus
        bot.send(message("/add"))
        assert "Send the listing link first" in last(bot.send(message(photo="p1")))
        assert len(listing_by_ref(db_session).images) == 0

    def test_photo_with_the_link_moves_the_entry_on(self, bot, db_session):
        bot.send(message("/add"))
        out = bot.send(message(photo="p1", caption=f"{LINK} £45"))
        assert last(out) == "Brand? (e.g. Stone Island)"
        bot.send(message("Stone Island"))
        listing = listing_by_ref(db_session)
        assert listing.raw_brand == "Stone Island"
        assert len(listing.images) == 1

    def test_listing_deleted_mid_conversation(self, bot, db_session):
        bot.send(message(LINK))  # asks for the price
        listing = listing_by_ref(db_session)
        db_session.delete(listing)
        db_session.commit()
        assert "no longer exists" in last(bot.send(message("45")))
        assert "Send me a Vinted link" in last(bot.send(message("hello")))  # conversation gone

    def test_expired_question(self, bot):
        out = bot.send(callback("f:skip"))
        assert [a.text for a in out.answers] == ["That question has expired."]


# --------------------------------------------------------------------------- commands


class TestCommands:
    def test_help_and_unknown(self, bot):
        assert "never buy anything" in last(bot.send(message("/help")))
        assert "never buy anything" in last(bot.send(message("/start")))
        assert "Unknown command /frobnicate" in last(bot.send(message("/frobnicate")))

    def test_check(self, bot, db_session):
        bot.send(message(f"{LINK} £45"))
        listing = listing_by_ref(db_session)
        assert bot.send(message(f"/check {listing.id}")).evaluations == [
            EvaluationRequest(listing.id, "manual")
        ]
        assert bot.send(message("/check")).evaluations == [
            EvaluationRequest(listing.id, "manual")
        ]  # the listing you are working on
        assert "There is no listing #999999" in last(bot.send(message("/check 999999")))
        assert "Usage: /check 12" in last(bot.send(message("/check abc")))

    def test_check_needs_a_live_listing(self, bot, db_session):
        bot.send(message(f"{LINK} £45"))
        listing = listing_by_ref(db_session)
        bot.send(message(f"/gone {listing.id}"))
        assert "is marked removed" in last(bot.send(message(f"/check {listing.id}")))

    def test_price(self, bot, db_session):
        bot.send(message(f"{LINK} £45"))
        listing = listing_by_ref(db_session)
        out = bot.send(message(f"/price {listing.id} £40"))
        assert out.evaluations == [EvaluationRequest(listing.id, "price_change")]
        assert listing_by_ref(db_session).price == Decimal(40)
        out = bot.send(message("/price £38"))
        assert out.evaluations == [EvaluationRequest(listing.id, "price_change")]
        assert "already has that price" in last(bot.send(message(f"/price #{listing.id} 38")))
        assert "Usage: /price" in last(bot.send(message(f"/price {listing.id}")))

    def test_sold_records_a_market_observation(self, bot, db_session):
        bot.send(message(f"{LINK} £95"))
        listing = listing_by_ref(db_session)
        # As identified by an evaluation:
        listing.brand_id = db_session.scalar(select(Brand.id).where(Brand.slug == "stone-island"))
        listing.category_id = db_session.scalar(
            select(Category.id).where(Category.slug == "sweatshirts")
        )
        listing.size_normalised = "L"
        db_session.commit()

        out = bot.send(message(f"/sold {listing.id}"))
        assert "saved as market data" in last(out)
        sale = db_session.scalar(select(MarketSale).where(MarketSale.listing_id == listing.id))
        assert sale.source == SaleSource.OBSERVED_SOLD_LISTING.value
        assert sale.price_type == PriceType.LAST_ASKING_PRICE.value
        assert sale.sale_price == Decimal(95)
        assert sale.size_normalised == "L"
        assert listing_by_ref(db_session).status == ListingStatus.SOLD.value
        assert "already marked sold" in last(bot.send(message(f"/sold {listing.id}")))

    def test_sold_without_identification(self, bot, db_session):
        bot.send(message(f"{LINK} £95"))
        listing = listing_by_ref(db_session)
        assert "not saved as market data" in last(bot.send(message(f"/sold {listing.id}")))
        assert db_session.scalar(select(func.count(MarketSale.id))) == 0

    def test_show_and_recent(self, bot, db_session, tmp_path):
        bot.send(message(f"{LINK} £45"))
        listing = listing_by_ref(db_session)
        out = bot.send(message(f"/show {listing.id}"))
        assert "has not been evaluated yet" in last(out)
        assert out.messages[-1].keyboard["inline_keyboard"][0][0]["callback_data"] == (
            f"e:{listing.id}"
        )
        evaluate(db_session, tmp_path, listing)
        text = last(bot.send(message(f"/show {listing.id}")))
        assert "NOT A DEAL" in text
        assert "Estimates only" in text
        recent = last(bot.send(message("/recent")))
        assert f"#{listing.id} stone island crewneck sweatshirt · £45.00 — rejected" in recent

    def test_recent_when_empty(self, bot):
        assert "No listings yet" in last(bot.send(message("/recent")))


class TestComps:
    def test_one_line(self, bot, db_session):
        out = bot.send(
            message("/comp Stone Island | sweatshirts | £95 | L | very good | 2026-09-20")
        )
        assert "Saved market sale" in last(out)
        assert "£95.00 · size L · Very good, sold 20 Sep 2026" in last(out)
        sale = db_session.scalar(select(MarketSale))
        assert sale.source == SaleSource.MANUAL_ENTRY.value
        assert sale.price_type == PriceType.FINAL_SALE_PRICE.value
        assert sale.created_by_user_id == operator(db_session).id
        again = bot.send(
            message("/comp Stone Island | sweatshirts | £95 | L | very good | 2026-09-20")
        )
        assert "already recorded" in last(again)

    def test_guided(self, bot, db_session):
        assert "Send the sold item as one line" in last(bot.send(message("/comp")))
        out = bot.send(message("CP Company | jackets | 120"))
        assert "Saved market sale" in last(out)
        assert db_session.scalar(select(func.count(MarketSale.id))) == 1

    @pytest.mark.parametrize(
        ("text", "error"),
        [
            ("/comp Stone Island | sweatshirts", "Send the sale as"),
            ("/comp Nobody | sweatshirts | 10", "unknown brand"),
        ],
    )
    def test_errors(self, bot, db_session, text, error):
        out = bot.send(message(text))
        assert last(out).startswith("⚠️")
        assert error in last(out)
        assert db_session.scalar(select(func.count(MarketSale.id))) == 0


# --------------------------------------------------------------------------- photos


class TestPhotos:
    def test_caption_with_link_and_price(self, bot, db_session, files):
        out = bot.send(message(photo="p1", caption=f"{LINK} £45"))
        listing = listing_by_ref(db_session)
        image = db_session.scalar(select(ListingImage))
        assert image.listing_id == listing.id
        assert (image.source, image.telegram_file_id, image.telegram_file_unique_id) == (
            "telegram",
            "p1",
            "u-p1",
        )
        assert out.evaluations == []  # more photos may follow: you tap Evaluate
        assert out.messages[-1].keyboard["inline_keyboard"][0][0]["callback_data"] == (
            f"e:{listing.id}"
        )
        assert files.downloads == ["p1"]  # the largest size, not the thumbnail

    def test_caption_without_price_asks_for_it(self, bot, db_session):
        assert "What is the asking price?" in last(bot.send(message(photo="p1", caption=LINK)))
        out = bot.send(message("45"))
        assert out.evaluations == [EvaluationRequest(listing_by_ref(db_session).id, "ingest")]

    def test_album(self, bot, db_session):
        first = bot.send(message(photo="p1", caption=f"{LINK} £45", media_group_id="g1"))
        second = bot.send(message(photo="p2", media_group_id="g1"))
        assert first.messages
        assert second.messages == []  # one reply per album
        assert len(listing_by_ref(db_session).images) == 2

    def test_photo_follows_the_listing_you_sent(self, bot, db_session):
        bot.send(message(f"{LINK} £45"))
        out = bot.send(message(photo="p1"))
        assert "Photos go with" in last(out)
        assert "(I already had that photo)" in last(bot.send(message(photo="p1")))
        assert len(listing_by_ref(db_session).images) == 1

    def test_photo_without_context(self, bot, db_session):
        assert "Send the listing link first" in last(bot.send(message(photo="p1")))
        assert db_session.scalar(select(func.count(ListingImage.id))) == 0

    def test_image_document(self, bot, db_session):
        bot.send(message(f"{LINK} £45"))
        document = {"file_id": "p3", "file_unique_id": "u3", "mime_type": "image/jpeg",
                    "file_size": 30_000}  # fmt: skip
        bot.send(message(document=document))
        assert len(listing_by_ref(db_session).images) == 1

    def test_too_large(self, bot, settings, files):
        files.files["p1-small"] = image_bytes(seed=9, size=(90, 90))
        bot.send(message(f"{LINK} £45"))
        out = bot.send(message(photo="p1", photo_size=settings.max_image_bytes + 1))
        # Only the thumbnail fits; it is used rather than failing.
        assert "Photos go with" in last(out)
        document = {"file_id": "p3", "mime_type": "image/png",
                    "file_size": settings.max_image_bytes + 1}  # fmt: skip
        assert "larger than" in last(bot.send(message(document=document)))

    def test_download_failure_rolls_everything_back(self, settings, test_db, db_session):
        failing = Harness(
            BotHandler(settings, FakeFiles(fail=True), clock=lambda: NOW), test_db, db_session
        )
        out = failing.send(message(photo="p1", caption=f"{LINK} £45"))
        assert "couldn't download that photo" in last(out)
        assert db_session.scalar(select(func.count(Listing.id))) == 0  # caption listing undone
        assert out.evaluations == []

    def test_not_an_image(self, bot, files, db_session):
        files.files["junk"] = b"%PDF-1.4 not an image"
        bot.send(message(f"{LINK} £45"))
        out = bot.send(message(photo="junk"))
        assert "not a valid image" in last(out)
        assert db_session.scalar(select(func.count(ListingImage.id))) == 0


# --------------------------------------------------------------------------- decisions


@pytest.fixture
def alert(db_session, tmp_path, recorder, bot):
    bot.send(message("/help"))  # the operator's first contact
    seed_comps(recorder)
    listing = listing_for(db_session)
    evaluation = evaluate(db_session, tmp_path, listing)
    row = Alert(
        evaluation_id=evaluation.id,
        listing_id=listing.id,
        chat_id=111,
        external_message_id=500,
        priority="review",
        status="sent",
    )
    db_session.add(row)
    db_session.commit()
    return row


class TestDecisions:
    def test_pass(self, bot, db_session, alert):
        out = bot.send(callback(f"a:{alert.id}:p"))
        db_session.refresh(alert)
        assert alert.user_decision == "pass"
        assert alert.decided_by_user_id == operator(db_session).id
        assert [a.text for a in out.answers] == ["Marked PASS"]
        (edit,) = out.edits
        assert (edit.chat_id, edit.message_id) == (111, 500)
        assert [b["text"] for b in edit.keyboard["inline_keyboard"][0]] == [
            "BUY",
            "✓ PASS",
            "REVIEW",
        ]
        audit = db_session.scalar(select(AuditLog).where(AuditLog.action == "alert.decision"))
        assert audit.after == {"user_decision": "pass"}

    def test_buy_with_estimated_costs(self, bot, db_session, alert):
        out = bot.send(callback(f"a:{alert.id}:b"))
        assert "Nothing has been bought" in last(out)
        out = bot.send(message("£45"))
        assert "Item £45.00 + Buyer Protection £2.95 + postage £2.99 = <b>£50.94</b>" in last(out)
        out = bot.send(callback("f:ok"))
        assert "Recorded purchase" in last(out)
        assert "expected profit" in last(out)

        purchase = db_session.scalar(select(Purchase))
        assert (purchase.purchase_price, purchase.buyer_protection_fee) == (
            Decimal("45.00"),
            Decimal("2.95"),
        )
        assert purchase.total_acquisition_cost == Decimal("50.94")
        assert (purchase.alert_id, purchase.evaluation_id) == (alert.id, alert.evaluation_id)
        item = db_session.scalar(select(InventoryItem))
        assert item.status == "ordered"
        assert item.allocated_acquisition_cost == Decimal("50.94")
        evaluation_net = Decimal(alert.evaluation.details["profit"]["net_proceeds"])
        assert item.expected_profit == evaluation_net - Decimal("50.94")
        prediction = db_session.scalar(select(PredictionResult))
        assert prediction.predicted_expected_sale == alert.evaluation.expected_sale_price
        assert prediction.predicted_comp_level == "L1"
        listing = db_session.get(Listing, alert.listing_id)
        assert listing.status == ListingStatus.SOLD.value  # bought by you...
        assert db_session.scalar(select(func.count(MarketSale.id))) == 10  # ...not a comp
        assert db_session.scalar(select(AuditLog).where(AuditLog.action == "purchase.create"))

    @pytest.mark.parametrize(
        ("answer", "fee", "postage", "total"),
        [
            ("51.20", "2.95", "3.25", "51.20"),
            ("total £46", "1.00", "0.00", "46.00"),
            ("2.95 3.49", "2.95", "3.49", "51.44"),
        ],
    )
    def test_buy_with_actual_costs(self, bot, db_session, alert, answer, fee, postage, total):
        bot.send(callback(f"a:{alert.id}:b"))
        bot.send(message("45"))
        out = bot.send(message(answer))
        assert f"= <b>£{total}</b>" in last(out)
        bot.send(callback("f:ok"))
        purchase = db_session.scalar(select(Purchase))
        assert (purchase.buyer_protection_fee, purchase.inbound_shipping) == (
            Decimal(fee),
            Decimal(postage),
        )
        assert purchase.total_acquisition_cost == Decimal(total)

    def test_buy_input_errors(self, bot, db_session, alert):
        bot.send(callback(f"a:{alert.id}:b"))
        assert "Send the item price you paid" in last(bot.send(message("no idea")))
        assert "priced in GBP" in last(bot.send(message("45 eur")))
        bot.send(message("45"))
        assert "can't be less than the item price" in last(bot.send(message("40")))
        assert "Tap Confirm" in last(bot.send(message("hmm")))  # still waiting to confirm
        assert last(bot.send(callback("f:cancel"))) == "Cancelled."
        assert db_session.scalar(select(func.count(Purchase.id))) == 0

    def test_buy_twice_and_pass_after_buy(self, bot, db_session, alert):
        bot.send(callback(f"a:{alert.id}:b"))
        out = bot.send(callback(f"a:{alert.id}:p"))
        assert "purchase entry cancelled" in last(out)
        bot.send(callback(f"a:{alert.id}:b"))
        bot.send(message("45"))
        bot.send(callback("f:ok"))
        out = bot.send(callback(f"a:{alert.id}:b"))
        assert "is already recorded" in last(out)
        assert "You recorded buying" in last(bot.send(message(f"/sold {alert.listing_id}")))

    def test_unknown_alert_and_invalid_buttons(self, bot):
        out = bot.send(callback("a:999999:b"))
        assert "alert 999999 not found" in last(out)
        assert out.answers
        assert [a.text for a in bot.send(callback("zzz")).answers] == [
            "This button is no longer valid."
        ]
        assert [a.text for a in bot.send(callback("n")).answers] == [None]

    def test_evaluate_button(self, bot, db_session, alert):
        out = bot.send(callback(f"e:{alert.listing_id}"))
        assert out.evaluations == [EvaluationRequest(alert.listing_id, "manual")]
        assert out.edits[0].keyboard is None
        assert "There is no listing #999999" in last(bot.send(callback("e:999999")))
