"""Purchases (incl. bundles), the inventory lifecycle, resales and their feedback loops."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import func, select

from app.config.loader import load_default_config
from app.core.enums import ConfigKind, InventoryStatus, ListingStatus, SaleSource
from app.core.errors import ConflictError, InvalidStateError, ValidationFailedError
from app.models import AuditLog, InventoryEvent, MarketSale, PredictionResult, Resale
from app.services.audit import Actor
from app.services.inventory import (
    cancel_resale,
    record_resale,
    transition_item,
    update_item,
    update_resale,
)
from app.services.pipeline import exposure_snapshot
from app.services.purchases import (
    PurchaseCosts,
    PurchaseItem,
    record_purchase,
    record_purchase_items,
)
from tests.factories import NOW
from tests.integration.test_notify import evaluate
from tests.integration.test_pipeline import listing_for, seed_comps

pytestmark = pytest.mark.integration

D = Decimal
FEES = load_default_config(ConfigKind.FEES)
ACTOR = Actor.system("test")
LATER = NOW + timedelta(days=3)


def events(db_session, item):
    return [
        e.to_status
        for e in db_session.scalars(
            select(InventoryEvent)
            .where(InventoryEvent.inventory_item_id == item.id)
            .order_by(InventoryEvent.id)
        )
    ]


def prediction(db_session, item):
    db_session.expire_all()
    return db_session.scalar(
        select(PredictionResult).where(PredictionResult.inventory_item_id == item.id)
    )


@pytest.fixture
def evaluated(db_session, tmp_path, recorder):
    seed_comps(recorder)
    listing = listing_for(db_session)
    return listing, evaluate(db_session, tmp_path, listing)


@pytest.fixture
def item(db_session, evaluated):
    listing, evaluation = evaluated
    _, bought = record_purchase(
        db_session, listing=listing, costs=PurchaseCosts(D("45.00"), D("2.95"), D("2.99")),
        currency="GBP", purchased_at=NOW, actor=ACTOR, evaluation=evaluation,
    )  # fmt: skip
    return bought


def sell(db_session, item, price="110.00", **kwargs):
    for status in (InventoryStatus.RECEIVED, InventoryStatus.LISTED):
        if item.status != InventoryStatus.LISTED.value:
            transition_item(db_session, item.id, status, at=NOW + timedelta(days=1), actor=ACTOR)
    return record_resale(
        db_session, item.id, sale_price=D(price), sold_at=LATER + timedelta(days=7), actor=ACTOR,
        fees=FEES, **kwargs,
    )  # fmt: skip


# --------------------------------------------------------------------------- purchases


class TestBundles:
    def second_listing(self, db_session, tmp_path, title="CP Company lens hoodie grey L"):
        listing = listing_for(
            db_session, title=title, raw_brand="CP Company", raw_category="Hoodies"
        )
        return listing, evaluate(db_session, tmp_path, listing)

    def test_split_by_expected_value(self, db_session, tmp_path, evaluated):
        first, first_eval = evaluated
        second, _ = self.second_listing(db_session, tmp_path)
        purchase, items = record_purchase_items(
            db_session,
            items=[
                PurchaseItem(listing=first, evaluation=first_eval),
                PurchaseItem(listing=second, expected_resale_price=D("55.00")),
            ],
            costs=PurchaseCosts(D("80.00"), D("4.70"), D("2.99")),
            currency="GBP", marketplace="vinted", purchased_at=NOW, actor=ACTOR,
        )  # fmt: skip
        assert purchase.item_count == 2
        assert purchase.total_acquisition_cost == D("87.69")
        expected = first_eval.expected_sale_price
        weights = [expected, D("55.00")]
        share = (D("87.69") * expected / sum(weights)).quantize(D("0.01"))
        assert abs(items[0].allocated_acquisition_cost - share) <= D("0.01")
        assert sum(i.allocated_acquisition_cost for i in items) == D("87.69")
        assert prediction(db_session, items[0]) is not None
        assert prediction(db_session, items[1]) is None  # no evaluation for the second
        assert {first.status, second.status} == {ListingStatus.SOLD.value}
        audit = db_session.scalar(select(AuditLog).where(AuditLog.action == "purchase.create"))
        assert audit.after["allocation"] == "expected_value"
        assert len(audit.after["items"]) == 2

    def test_equal_and_manual(self, db_session):
        spec = [PurchaseItem(title="Burberry scarf"), PurchaseItem(title="Ralph Lauren polo")]
        _, items = record_purchase_items(
            db_session, items=spec, costs=PurchaseCosts(D("30.01")), currency="GBP",
            marketplace="vinted", purchased_at=NOW, actor=ACTOR, allocation="equal",
        )  # fmt: skip
        assert [i.allocated_acquisition_cost for i in items] == [D("15.01"), D("15.00")]
        manual = [
            PurchaseItem(title="a", allocated_cost=D("10.00")),
            PurchaseItem(title="b", allocated_cost=D("20.00")),
        ]
        _, items = record_purchase_items(
            db_session, items=manual, costs=PurchaseCosts(D("30.00")), currency="GBP",
            marketplace="vinted", purchased_at=NOW, actor=ACTOR, allocation="manual",
        )  # fmt: skip
        assert [i.allocated_acquisition_cost for i in items] == [D("10.00"), D("20.00")]

    @pytest.mark.parametrize(
        ("items", "allocation", "message"),
        [
            (
                [PurchaseItem(title="a"), PurchaseItem(title="b")],
                "expected_value",
                "needs an expected",
            ),
            (
                [PurchaseItem(title="a", allocated_cost=D(5)), PurchaseItem(title="b")],
                "manual",
                "needs a cost for every item",
            ),
            (
                [
                    PurchaseItem(title="a", allocated_cost=D(5)),
                    PurchaseItem(title="b", allocated_cost=D(5)),
                ],
                "manual",
                "add up to 10, not the total 30",
            ),
            ([PurchaseItem()], "equal", "needs a title"),
            ([], "equal", "at least one item"),
        ],
    )
    def test_invalid(self, db_session, items, allocation, message):
        with pytest.raises(ValidationFailedError, match=message):
            record_purchase_items(
                db_session, items=items, costs=PurchaseCosts(D("30.00")), currency="GBP",
                marketplace="vinted", purchased_at=NOW, actor=ACTOR, allocation=allocation,
            )  # fmt: skip

    def test_listing_once_only(self, db_session, evaluated, item):
        listing, _ = evaluated
        with pytest.raises(ValidationFailedError, match="twice"):
            record_purchase_items(
                db_session, items=[PurchaseItem(listing=listing), PurchaseItem(listing=listing)],
                costs=PurchaseCosts(D(1)), currency="GBP", marketplace="vinted",
                purchased_at=NOW, actor=ACTOR, allocation="equal",
            )  # fmt: skip
        with pytest.raises(ConflictError, match="already recorded"):
            record_purchase_items(
                db_session, items=[PurchaseItem(listing=listing)], costs=PurchaseCosts(D(1)),
                currency="GBP", marketplace="vinted", purchased_at=NOW, actor=ACTOR,
            )  # fmt: skip


# --------------------------------------------------------------------------- lifecycle


class TestLifecycle:
    def test_receive_list_and_events(self, db_session, item):
        transition_item(
            db_session, item.id, InventoryStatus.RECEIVED, at=NOW + timedelta(days=2),
            actor=ACTOR, condition="very good",
        )  # fmt: skip
        transition_item(
            db_session, item.id, InventoryStatus.LISTED, at=LATER, actor=ACTOR,
            listed_price=D("115.00"), listing_channel="vinted",
            listing_url="https://www.vinted.co.uk/items/1",
        )  # fmt: skip
        assert item.condition_on_receipt == "very_good"
        assert (item.listed_at, item.listed_price, item.listing_channel) == (
            LATER,
            D("115.00"),
            "vinted",
        )
        assert events(db_session, item) == ["ordered", "received", "listed"]
        assert (
            db_session.scalar(
                select(func.count(AuditLog.id)).where(AuditLog.action == "inventory.status")
            )
            == 2
        )

    @pytest.mark.parametrize(
        ("target", "message"),
        [
            (InventoryStatus.SOLD, "record the sale"),
            (InventoryStatus.SHIPPED, "can't become shipped"),
            (InventoryStatus.ORDERED, "already ordered"),
        ],
    )
    def test_invalid_transitions(self, db_session, item, target, message):
        with pytest.raises(InvalidStateError, match=message):
            transition_item(db_session, item.id, target, at=LATER, actor=ACTOR)

    def test_dates_and_conditions_are_checked(self, db_session, item):
        with pytest.raises(ValidationFailedError, match="before the purchase"):
            transition_item(
                db_session, item.id, InventoryStatus.RECEIVED, at=NOW - timedelta(days=1),
                actor=ACTOR,
            )  # fmt: skip
        with pytest.raises(ValidationFailedError, match="unknown condition"):
            transition_item(
                db_session, item.id, InventoryStatus.RECEIVED, at=LATER, actor=ACTOR,
                condition="mint",
            )  # fmt: skip

    def test_costs(self, db_session, item):
        update_item(
            db_session, item.id, actor=ACTOR, at=LATER, cleaning_cost=D("4.00"),
            repair_cost=D("6.00"), notes="new zip",
        )  # fmt: skip
        assert item.total_cost_basis == D("60.94")
        with pytest.raises(ValidationFailedError, match="must not be negative"):
            update_item(db_session, item.id, actor=ACTOR, at=LATER, other_costs=D("-1"))
        with pytest.raises(ValidationFailedError, match="whole pennies"):
            update_item(db_session, item.id, actor=ACTOR, at=LATER, other_costs=D("1.005"))

    def test_write_off_resolves_the_prediction(self, db_session, item):
        transition_item(db_session, item.id, InventoryStatus.WRITTEN_OFF, at=LATER, actor=ACTOR)
        row = prediction(db_session, item)
        assert (row.actual_profit, row.actual_roi, row.actual_sale_price) == (
            D("-50.94"),
            D("-1.0000"),
            None,
        )
        assert row.resolved_at == LATER
        update_item(db_session, item.id, actor=ACTOR, at=LATER, other_costs=D("1.00"))
        assert prediction(db_session, item).actual_profit == D("-51.94")

    def test_exposure_follows_the_stock(self, db_session, item):
        assert exposure_snapshot(db_session, item.product_id).unsold_cost == D("50.94")
        sell(db_session, item)
        assert exposure_snapshot(db_session, item.product_id).unsold_cost == D(0)


# --------------------------------------------------------------------------- resales


class TestResales:
    def test_sale_feeds_market_data_and_scores_the_prediction(self, db_session, item):
        resale = sell(db_session, item)
        # Defaults from the fee settings: no selling fee, £0.50 packaging.
        assert (resale.selling_fees, resale.other_selling_costs) == (D("0.00"), D("0.50"))
        assert resale.net_proceeds == D("109.50")
        assert resale.channel == "vinted"
        assert item.status == InventoryStatus.SOLD.value
        assert events(db_session, item)[-1] == "sold"

        sale = db_session.get(MarketSale, resale.market_sale_id)
        assert sale.source == SaleSource.OWN_SALE.value
        assert (sale.inventory_item_id, sale.product_id) == (item.id, item.product_id)
        assert sale.sale_price == D("110.00")
        assert sale.days_to_sale == 9  # listed on day 1, sold on day 10

        row = prediction(db_session, item)
        assert row.actual_sale_price == D("110.00")
        assert row.actual_profit == D("58.56")  # 109.50 − 50.94
        assert row.actual_days_to_sale == 9
        assert row.price_error == D("110.00") - row.predicted_expected_sale
        assert row.actual_within_quick_optimistic is (
            row.predicted_quick_sale <= D(110) <= row.predicted_optimistic_sale
        )

    def test_explicit_costs(self, db_session, item):
        resale = sell(
            db_session, item, "100.00", selling_fees=D("5.00"), outbound_shipping_cost=D("3.20"),
            shipping_charged_to_buyer=D("3.20"), other_selling_costs=D("0"), channel="eBay",
        )  # fmt: skip
        assert resale.net_proceeds == D("95.00")
        assert resale.channel == "ebay"
        assert db_session.get(MarketSale, resale.market_sale_id).marketplace == "ebay"

    def test_sale_errors(self, db_session, item):
        with pytest.raises(InvalidStateError, match="can't be sold"):
            record_resale(
                db_session, item.id, sale_price=D(10), sold_at=LATER, actor=ACTOR, fees=FEES
            )
        transition_item(db_session, item.id, InventoryStatus.RECEIVED, at=LATER, actor=ACTOR)
        with pytest.raises(ValidationFailedError, match="bought in GBP"):
            record_resale(
                db_session, item.id, sale_price=D(10), sold_at=LATER, actor=ACTOR, fees=FEES,
                currency="EUR",
            )  # fmt: skip
        with pytest.raises(ValidationFailedError, match="before the purchase"):
            record_resale(
                db_session, item.id, sale_price=D(10), sold_at=NOW - timedelta(days=1),
                actor=ACTOR, fees=FEES,
            )  # fmt: skip
        with pytest.raises(ValidationFailedError, match="must be positive"):
            record_resale(
                db_session, item.id, sale_price=D(0), sold_at=LATER, actor=ACTOR, fees=FEES
            )
        record_resale(db_session, item.id, sale_price=D(10), sold_at=LATER, actor=ACTOR, fees=FEES)
        with pytest.raises(ConflictError, match="already recorded"):
            record_resale(
                db_session, item.id, sale_price=D(10), sold_at=LATER, actor=ACTOR, fees=FEES
            )

    def test_unidentified_item_is_not_market_data(self, db_session):
        _, (loose,) = record_purchase_items(
            db_session, items=[PurchaseItem(title="Mystery jacket")], costs=PurchaseCosts(D(20)),
            currency="GBP", marketplace="vinted", purchased_at=NOW, actor=ACTOR,
        )  # fmt: skip
        resale = sell(db_session, loose, "35.00")
        assert resale.market_sale_id is None
        assert resale.net_proceeds == D("34.50")

    def test_refund_and_corrections(self, db_session, item):
        resale = sell(db_session, item)
        update_resale(
            db_session, resale.id, actor=ACTOR, at=LATER,
            changes={"refunds": D("10.00"), "paid_out_at": LATER, "notes": "partial refund"},
        )  # fmt: skip
        assert resale.net_proceeds == D("99.50")
        assert prediction(db_session, item).actual_profit == D("48.56")
        update_resale(
            db_session, resale.id, actor=ACTOR, at=LATER,
            changes={"sale_price": D("105.00"), "sold_at": LATER + timedelta(days=10)},
        )  # fmt: skip
        sale = db_session.get(MarketSale, resale.market_sale_id)
        assert (sale.sale_price, sale.days_to_sale) == (
            D("105.00"),
            12,
        )  # listed day 1, sold day 13
        with pytest.raises(ValidationFailedError, match="before the purchase"):
            update_resale(
                db_session, resale.id, actor=ACTOR, at=LATER,
                changes={"sold_at": NOW - timedelta(days=1)},
            )  # fmt: skip

    def test_cancel_before_completion(self, db_session, item):
        resale = sell(db_session, item)
        market_sale_id = resale.market_sale_id
        transition_item(db_session, item.id, InventoryStatus.SHIPPED, at=LATER, actor=ACTOR)
        cancel_resale(db_session, resale.id, actor=ACTOR, at=LATER, reason="buyer cancelled")
        db_session.expire_all()
        assert item.status == InventoryStatus.LISTED.value
        assert db_session.get(Resale, resale.id) is None
        assert db_session.get(MarketSale, market_sale_id) is None
        row = prediction(db_session, item)
        assert (row.actual_sale_price, row.resolved_at) == (None, None)
        assert events(db_session, item)[-1] == "listed"
        # It can be sold again.
        again = record_resale(
            db_session, item.id, sale_price=D("100"), sold_at=LATER + timedelta(days=9),
            actor=ACTOR, fees=FEES,
        )  # fmt: skip
        assert again.net_proceeds == D("99.50")

    def test_completed_sale_cannot_be_cancelled(self, db_session, item):
        resale = sell(db_session, item)
        transition_item(db_session, item.id, InventoryStatus.COMPLETED, at=LATER, actor=ACTOR)
        with pytest.raises(InvalidStateError, match="record the refund"):
            cancel_resale(db_session, resale.id, actor=ACTOR, at=LATER)

    def test_extra_costs_after_the_sale_rescore(self, db_session, item):
        sell(db_session, item)
        update_item(db_session, item.id, actor=ACTOR, at=LATER, cleaning_cost=D("5.00"))
        assert prediction(db_session, item).actual_profit == D("53.56")
