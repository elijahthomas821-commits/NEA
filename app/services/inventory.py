"""Inventory lifecycle, costs and resales.

* Status changes follow :mod:`app.analysis.inventory.lifecycle`; every change is an
  ``inventory_events`` row and an audit entry.
* Recording a sale stores its figures, marks the item sold, adds the sale to your market data
  (source ``own_sale`` — your best comps) and resolves the prediction made when you bought it.
* A sale that falls through before completion can be cancelled; the item goes back on sale and
  the market data and prediction outcome are withdrawn.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.inventory.lifecycle import TransitionError, can_sell, check_transition
from app.analysis.inventory.outcomes import (
    Outcome,
    Prediction,
    SaleFigures,
    sale_outcome,
    write_off_outcome,
)
from app.analysis.normalisation.condition import match_condition_label
from app.analysis.profit.fees import compute_fee
from app.collectors.base import RawSale
from app.config.schemas import FeesConfig
from app.core.enums import InventoryStatus, PriceType, SaleSource
from app.core.errors import ConflictError, InvalidStateError, NotFoundError, ValidationFailedError
from app.core.money import ZERO, normalise_currency
from app.core.time import days_between
from app.models import (
    Brand,
    Category,
    InventoryEvent,
    InventoryItem,
    Marketplace,
    MarketSale,
    PredictionResult,
    Product,
    Resale,
)
from app.services import audit
from app.services.audit import Actor
from app.services.market_data import record_sale_with_active_config

COST_FIELDS = ("cleaning_cost", "repair_cost", "other_costs")
RESALE_FIELDS = (
    "sale_price",
    "shipping_charged_to_buyer",
    "selling_fees",
    "outbound_shipping_cost",
    "refunds",
    "other_selling_costs",
)


def get_item(session: Session, item_id: int, *, lock: bool = False) -> InventoryItem:
    item = session.get(InventoryItem, item_id, with_for_update=lock or None)
    if item is None:
        raise NotFoundError(f"inventory item {item_id} not found")
    return item


def get_resale(session: Session, resale_id: int) -> Resale:
    resale = session.get(Resale, resale_id, with_for_update=True)
    if resale is None:
        raise NotFoundError(f"sale {resale_id} not found")
    return resale


def _event(
    session: Session,
    item: InventoryItem,
    target: InventoryStatus,
    *,
    at: datetime,
    actor: Actor,
    note: str | None,
) -> None:
    session.add(
        InventoryEvent(
            inventory_item_id=item.id,
            from_status=item.status,
            to_status=target.value,
            occurred_at=at,
            note=note[:500] if note else None,
            actor_user_id=actor.user_id,
        )
    )
    item.status = target.value


def _money_field(name: str, value: Decimal) -> Decimal:
    if value < 0:
        raise ValidationFailedError(f"{name.replace('_', ' ')} must not be negative")
    if value != value.quantize(Decimal("0.01")):
        raise ValidationFailedError(f"{name.replace('_', ' ')} must be in whole pennies")
    return value


# --------------------------------------------------------------------------- lifecycle


def transition_item(
    session: Session,
    item_id: int,
    target: InventoryStatus,
    *,
    at: datetime,
    actor: Actor,
    note: str | None = None,
    listed_price: Decimal | None = None,
    listing_channel: str | None = None,
    listing_url: str | None = None,
    condition: str | None = None,
) -> InventoryItem:
    item = get_item(session, item_id, lock=True)
    try:
        check_transition(InventoryStatus(item.status), target)
    except TransitionError as exc:
        raise InvalidStateError(str(exc)) from None
    purchased_at = item.purchase.purchased_at
    if at < purchased_at:
        raise ValidationFailedError("that date is before the purchase")
    before = audit.snapshot(item, ["status", "listed_price", "listed_at", "received_at"])

    if target is InventoryStatus.RECEIVED:
        item.received_at = at
        if condition:
            label = match_condition_label(condition)
            if label is None:
                raise ValidationFailedError(f"unknown condition {condition!r}")
            item.condition_on_receipt = label.value
    elif target is InventoryStatus.LISTED:
        item.listed_at = at  # the latest time it went on sale
        if listed_price is not None:
            item.listed_price = _money_field("listed_price", listed_price)
        item.listing_channel = listing_channel or item.listing_channel
        item.listing_url = listing_url or item.listing_url
    _event(session, item, target, at=at, actor=actor, note=note)
    if target is InventoryStatus.WRITTEN_OFF:
        _resolve(session, item, write_off_outcome(cost_basis=item.total_cost_basis), at=at)
    audit.record(
        session, actor, action="inventory.status", entity_type="inventory_item",
        entity_id=item.id, before=before,
        after=audit.snapshot(item, ["status", "listed_price", "listed_at", "received_at"]),
    )  # fmt: skip
    session.flush()
    return item


def update_item(
    session: Session,
    item_id: int,
    *,
    actor: Actor,
    at: datetime,
    cleaning_cost: Decimal | None = None,
    repair_cost: Decimal | None = None,
    other_costs: Decimal | None = None,
    listed_price: Decimal | None = None,
    listing_url: str | None = None,
    notes: str | None = None,
) -> InventoryItem:
    """Costs you add after buying (cleaning, repairs...) and listing details."""
    item = get_item(session, item_id, lock=True)
    fields = ["cleaning_cost", "repair_cost", "other_costs", "listed_price", "listing_url", "notes"]
    before = audit.snapshot(item, fields)
    for name, value in (
        ("cleaning_cost", cleaning_cost),
        ("repair_cost", repair_cost),
        ("other_costs", other_costs),
        ("listed_price", listed_price),
    ):
        if value is not None:
            setattr(item, name, _money_field(name, value))
    if listing_url is not None:
        item.listing_url = listing_url
    if notes is not None:
        item.notes = notes
    session.flush()
    # A different cost basis changes the outcome of a sale or write-off already recorded.
    if item.resale is not None:
        _resolve(session, item, _outcome_for(session, item, item.resale), at=at)
    elif item.status == InventoryStatus.WRITTEN_OFF.value:
        _resolve(session, item, write_off_outcome(cost_basis=item.total_cost_basis), at=at)
    audit.record(
        session, actor, action="inventory.update", entity_type="inventory_item",
        entity_id=item.id, before=before, after=audit.snapshot(item, fields),
    )  # fmt: skip
    return item


# --------------------------------------------------------------------------- resales


def default_selling_costs(
    sale_price: Decimal, channel: str, currency: str, fees: FeesConfig
) -> dict[str, Decimal]:
    """Selling fee, postage you pay and packaging from your fee settings, when they apply."""
    rules = fees.selling_channels.get(channel)
    if rules is None or currency != fees.currency:
        return {"selling_fees": ZERO, "outbound_shipping_cost": ZERO, "other_selling_costs": ZERO}
    return {
        "selling_fees": compute_fee(rules.selling_fee, sale_price),
        "outbound_shipping_cost": rules.outbound_shipping_paid_by_seller,
        "other_selling_costs": rules.packaging_cost + rules.other_selling_costs,
    }


def record_resale(
    session: Session,
    item_id: int,
    *,
    sale_price: Decimal,
    sold_at: datetime,
    actor: Actor,
    fees: FeesConfig,
    channel: str | None = None,
    currency: str | None = None,
    selling_fees: Decimal | None = None,
    outbound_shipping_cost: Decimal | None = None,
    shipping_charged_to_buyer: Decimal = ZERO,
    refunds: Decimal = ZERO,
    other_selling_costs: Decimal | None = None,
    notes: str | None = None,
) -> Resale:
    """You sold the item. Missing costs default to your fee settings for the channel."""
    item = get_item(session, item_id, lock=True)
    if item.resale is not None:
        raise ConflictError(f"a sale is already recorded for item {item.id}")
    if not can_sell(InventoryStatus(item.status)):
        raise InvalidStateError(f"an item that is {item.status} can't be sold")
    if sale_price <= 0:
        raise ValidationFailedError("the sale price must be positive")
    currency = normalise_currency(currency) if currency else item.currency
    if currency != item.currency:
        raise ValidationFailedError(
            f"this item was bought in {item.currency}; record the sale in it"
        )
    if sold_at < item.purchase.purchased_at:
        raise ValidationFailedError("the sale date is before the purchase")
    channel = (channel or fees.default_selling_channel).strip().lower()[:32]
    defaults = default_selling_costs(sale_price, channel, currency, fees)
    figures = SaleFigures(
        sale_price=_money_field("sale_price", sale_price),
        shipping_charged_to_buyer=_money_field(
            "shipping_charged_to_buyer", shipping_charged_to_buyer
        ),
        selling_fees=_money_field(
            "selling_fees", selling_fees if selling_fees is not None else defaults["selling_fees"]
        ),
        outbound_shipping_cost=_money_field(
            "outbound_shipping_cost",
            outbound_shipping_cost
            if outbound_shipping_cost is not None
            else defaults["outbound_shipping_cost"],
        ),
        refunds=_money_field("refunds", refunds),
        other_selling_costs=_money_field(
            "other_selling_costs",
            other_selling_costs
            if other_selling_costs is not None
            else defaults["other_selling_costs"],
        ),
    )
    resale = Resale(
        inventory_item_id=item.id,
        channel=channel,
        sold_at=sold_at,
        currency=currency,
        net_proceeds=figures.net_proceeds,
        notes=notes,
        **{name: getattr(figures, name) for name in RESALE_FIELDS},
    )
    session.add(resale)
    session.flush()
    _event(session, item, InventoryStatus.SOLD, at=sold_at, actor=actor, note=f"sold ({channel})")
    session.flush()
    session.refresh(item, ["resale"])
    market_sale = _record_own_sale(session, item, resale, actor)
    resale.market_sale_id = market_sale.id if market_sale else None
    _resolve(session, item, _outcome_for(session, item, resale), at=sold_at)
    audit.record(
        session, actor, action="resale.create", entity_type="resale", entity_id=resale.id,
        after={**audit.snapshot(resale, [*RESALE_FIELDS, "net_proceeds", "channel", "sold_at"]),
               "inventory_item_id": item.id},
    )  # fmt: skip
    session.flush()
    return resale


def update_resale(
    session: Session,
    resale_id: int,
    *,
    actor: Actor,
    at: datetime,
    changes: dict[str, Any],
) -> Resale:
    """Correct a sale or add what happened later (a refund, the payout date)."""
    resale = get_resale(session, resale_id)
    item = get_item(session, resale.inventory_item_id, lock=True)
    # Read and check everything before changing anything: the table requires net proceeds to
    # match the other figures at every flush.
    purchased_at = item.purchase.purchased_at
    market_sale = session.get(MarketSale, resale.market_sale_id) if resale.market_sale_id else None
    updates = {
        name: _money_field(name, changes[name])
        for name in RESALE_FIELDS
        if changes.get(name) is not None
    }
    if updates.get("sale_price", resale.sale_price) <= 0:
        raise ValidationFailedError("the sale price must be positive")
    sold_at = changes.get("sold_at")
    if sold_at is not None and sold_at < purchased_at:
        raise ValidationFailedError("the sale date is before the purchase")

    tracked = [*RESALE_FIELDS, "net_proceeds", "sold_at", "paid_out_at", "notes"]
    before = audit.snapshot(resale, tracked)
    with session.no_autoflush:
        for name, value in updates.items():
            setattr(resale, name, value)
        resale.net_proceeds = _figures(resale).net_proceeds
        if sold_at is not None:
            resale.sold_at = sold_at
        if "paid_out_at" in changes:
            resale.paid_out_at = changes["paid_out_at"]
        if changes.get("notes") is not None:
            resale.notes = changes["notes"]
        if market_sale is not None:
            market_sale.sale_price = resale.sale_price
            market_sale.sold_at = resale.sold_at
            if market_sale.listed_at is not None:
                market_sale.days_to_sale = max(
                    days_between(market_sale.listed_at, resale.sold_at), 0
                )
    session.flush()
    _resolve(session, item, _outcome_for(session, item, resale), at=at)
    audit.record(
        session, actor, action="resale.update", entity_type="resale", entity_id=resale.id,
        before=before, after=audit.snapshot(resale, tracked),
    )  # fmt: skip
    return resale


def cancel_resale(
    session: Session, resale_id: int, *, actor: Actor, at: datetime, reason: str | None = None
) -> InventoryItem:
    """The sale fell through (before completion): the item goes back on sale."""
    resale = get_resale(session, resale_id)
    item = get_item(session, resale.inventory_item_id, lock=True)
    if item.status == InventoryStatus.COMPLETED.value:
        raise InvalidStateError(
            "a completed sale can't be cancelled; record the refund on the sale instead"
        )
    before = audit.snapshot(resale, [*RESALE_FIELDS, "net_proceeds", "sold_at", "channel"])
    market_sale_id = resale.market_sale_id
    session.delete(resale)
    session.flush()
    if market_sale_id is not None:
        market_sale = session.get(MarketSale, market_sale_id)
        if market_sale is not None:
            session.delete(market_sale)
    target = InventoryStatus.LISTED if item.listed_at else InventoryStatus.READY_TO_LIST
    _event(
        session, item, target, at=at, actor=actor, note=f"sale cancelled: {reason or 'no reason'}"
    )
    _resolve(session, item, None, at=at)
    audit.record(
        session, actor, action="resale.cancel", entity_type="resale", entity_id=resale_id,
        before=before, after={"reason": reason, "inventory_item_id": item.id},
    )  # fmt: skip
    session.flush()
    session.expire(item, ["resale"])
    return item


def _figures(resale: Resale) -> SaleFigures:
    return SaleFigures(**{name: getattr(resale, name) for name in RESALE_FIELDS})


def _outcome_for(session: Session, item: InventoryItem, resale: Resale) -> Outcome:
    return sale_outcome(
        _figures(resale),
        cost_basis=item.total_cost_basis,
        prediction=item_prediction(session, item.id),
        started_at=item.listed_at or item.purchase.purchased_at,
        sold_at=resale.sold_at,
    )


def item_prediction(session: Session, item_id: int) -> Prediction:
    row = session.scalar(
        select(PredictionResult).where(PredictionResult.inventory_item_id == item_id)
    )
    if row is None:
        return Prediction()
    return Prediction(
        quick=row.predicted_quick_sale,
        expected=row.predicted_expected_sale,
        optimistic=row.predicted_optimistic_sale,
    )


def _resolve(
    session: Session, item: InventoryItem, outcome: Outcome | None, *, at: datetime
) -> None:
    """Write (or with ``None``, clear) the actual outcome on the item's prediction record."""
    row = session.scalar(
        select(PredictionResult).where(PredictionResult.inventory_item_id == item.id)
    )
    if row is None:
        return
    row.actual_sale_price = outcome.actual_sale_price if outcome else None
    row.actual_profit = outcome.actual_profit if outcome else None
    row.actual_roi = outcome.actual_roi if outcome else None
    row.actual_days_to_sale = outcome.actual_days_to_sale if outcome else None
    row.price_error = outcome.price_error if outcome else None
    row.price_error_pct = outcome.price_error_pct if outcome else None
    row.actual_within_quick_optimistic = outcome.within_range if outcome else None
    row.resolved_at = at if outcome else None
    session.flush()


def _record_own_sale(
    session: Session, item: InventoryItem, resale: Resale, actor: Actor
) -> MarketSale | None:
    """Your sale becomes market data (the most trusted kind), when the item is identified."""
    brand = session.get(Brand, item.brand_id) if item.brand_id else None
    category = session.get(Category, item.category_id) if item.category_id else None
    if brand is None or category is None:
        return None
    product = session.get(Product, item.product_id) if item.product_id else None
    if product is not None and (product.brand_id, product.category_id) != (brand.id, category.id):
        product = None
    listed_at = min(item.listed_at, resale.sold_at) if item.listed_at else None
    raw = RawSale(
        source=SaleSource.OWN_SALE,
        source_ref=f"resale:{resale.id}",
        marketplace=resale.channel if session.get(Marketplace, resale.channel) else None,
        title=item.title[:300] or None,
        brand=brand.slug,
        category=category.slug,
        product=product.slug if product else None,
        size=item.size_normalised,
        colour=item.colour,
        condition=item.condition_on_receipt,
        sale_price=resale.sale_price,
        currency=resale.currency,
        price_type=PriceType.FINAL_SALE_PRICE,
        listed_at=listed_at,
        sold_at=resale.sold_at,
        notes="your own sale",
    )
    try:
        row, _ = record_sale_with_active_config(
            session, raw, actor=actor, inventory_item_id=item.id
        )
    except ValidationFailedError:
        return None
    return row
