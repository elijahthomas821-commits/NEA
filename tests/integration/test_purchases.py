"""Recording purchases you made yourself (the system never buys anything)."""

from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy import func, select

from app.config.loader import load_default_config
from app.core.enums import ConfigKind, ListingStatus
from app.core.errors import ConflictError, ValidationFailedError
from app.models import InventoryEvent, PredictionResult
from app.services.audit import Actor
from app.services.ingestion import update_listing
from app.services.purchases import (
    PurchaseCosts,
    estimate_costs,
    record_purchase,
    with_total_paid,
)
from tests.factories import NOW
from tests.integration.test_notify import evaluate
from tests.integration.test_pipeline import listing_for, seed_comps

pytestmark = pytest.mark.integration

D = Decimal
FEES = load_default_config(ConfigKind.FEES)
ACTOR = Actor.system("test")


def test_estimate_costs_from_fee_settings():
    costs = estimate_costs(D("45.00"), "GBP", FEES)  # type: ignore[arg-type]
    assert (costs.buyer_fee, costs.inbound_shipping, costs.total) == (
        D("2.95"),
        D("2.99"),
        D("50.94"),
    )
    other = estimate_costs(D("45.00"), "EUR", FEES)  # type: ignore[arg-type]
    assert (other.buyer_fee, other.inbound_shipping) == (0, 0)  # rules are in GBP


@pytest.mark.parametrize(
    ("costs", "message"),
    [
        (PurchaseCosts(purchase_price=D(0)), "must be positive"),
        (PurchaseCosts(purchase_price=D(10), buyer_fee=D(-1)), "buyer fee"),
        (PurchaseCosts(purchase_price=D(10), inbound_shipping=D(-1)), "inbound shipping"),
    ],
)
def test_invalid_costs(db_session, costs, message):
    listing = listing_for(db_session)
    with pytest.raises(ValidationFailedError, match=message):
        record_purchase(
            db_session, listing=listing, costs=costs, currency="GBP", purchased_at=NOW,
            actor=ACTOR,
        )  # fmt: skip


def test_without_an_evaluation(db_session):
    listing = listing_for(db_session)
    purchase, item = record_purchase(
        db_session, listing=listing, costs=PurchaseCosts(purchase_price=D("30"), other=D("1")),
        currency="GBP", purchased_at=NOW, actor=ACTOR, notes="bundle deal",
    )  # fmt: skip
    assert purchase.total_acquisition_cost == D("31")
    assert (item.expected_resale_price, item.expected_profit) == (None, None)
    assert db_session.scalar(select(func.count(PredictionResult.id))) == 0
    event = db_session.scalar(select(InventoryEvent))
    assert (event.to_status, event.inventory_item_id) == ("ordered", item.id)
    assert listing.status == ListingStatus.SOLD.value
    with pytest.raises(ConflictError, match="already recorded"):
        record_purchase(
            db_session, listing=listing, costs=PurchaseCosts(purchase_price=D("30")),
            currency="GBP", purchased_at=NOW, actor=ACTOR,
        )  # fmt: skip


def test_listing_already_gone_keeps_its_status(db_session):
    listing = listing_for(db_session)
    update_listing(db_session, listing.id, now=NOW, status=ListingStatus.REMOVED)
    record_purchase(
        db_session, listing=listing, costs=PurchaseCosts(purchase_price=D("30")),
        currency="GBP", purchased_at=NOW, actor=ACTOR,
    )  # fmt: skip
    assert listing.status == ListingStatus.REMOVED.value


def test_prediction_snapshot(db_session, tmp_path, recorder):
    seed_comps(recorder)
    listing = listing_for(db_session)
    evaluation = evaluate(db_session, tmp_path, listing)
    _, item = record_purchase(
        db_session, listing=listing, costs=PurchaseCosts(purchase_price=D("40")),
        currency="GBP", purchased_at=NOW, actor=ACTOR, evaluation=evaluation,
    )  # fmt: skip
    net = D(evaluation.details["profit"]["net_proceeds"])
    assert item.expected_profit == net - D(40)
    prediction = db_session.scalar(select(PredictionResult))
    assert prediction.predicted_profit == net - D(40)
    assert prediction.predicted_roi == ((net - D(40)) / D(40)).quantize(D("0.0001"))
    assert prediction.model_version == evaluation.pipeline_version
    assert not prediction.predicted_from_price_guide


def test_currency_mismatch_has_no_expected_profit(db_session, tmp_path, recorder):
    seed_comps(recorder)
    listing = listing_for(db_session)
    evaluation = evaluate(db_session, tmp_path, listing)
    _, item = record_purchase(
        db_session, listing=listing, costs=PurchaseCosts(purchase_price=D("40")),
        currency="EUR", purchased_at=NOW, actor=ACTOR, evaluation=evaluation,
    )  # fmt: skip
    assert item.expected_profit is None


def test_documented_example():
    """docs/financial-calculations.md section 10."""
    from types import SimpleNamespace

    from app.services.purchases import _expected_profit

    estimate = estimate_costs(D("45.00"), "GBP", FEES)  # type: ignore[arg-type]
    costs = with_total_paid(estimate, D("51.20"))
    assert (costs.buyer_fee, costs.inbound_shipping) == (D("2.95"), D("3.25"))
    # A total below item price + fee: the fee is capped, postage is zero.
    assert with_total_paid(estimate, D("46")) == PurchaseCosts(D("45.00"), D("1.00"), D("0.00"))
    with pytest.raises(ValidationFailedError, match="less than the item price"):
        with_total_paid(estimate, D("44"))
    evaluation = SimpleNamespace(currency="GBP", details={"profit": {"net_proceeds": "107.30"}})
    profit = _expected_profit(evaluation, costs.total, "GBP")  # type: ignore[arg-type]
    assert profit == D("56.10")
    assert f"{profit / costs.total:.1%}" == "109.6%"
