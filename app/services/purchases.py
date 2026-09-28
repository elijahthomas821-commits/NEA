"""Recording purchases you made yourself.

The system never buys anything. After you buy an item on the marketplace, you record what you
actually paid; that creates the purchase, an inventory item (status ``ordered``) and a snapshot
of what the evaluation predicted, so the prediction can be checked against the real outcome
once the item sells.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.profit.model import Extras, acquisition_costs
from app.config.schemas import FeesConfig
from app.core.enums import InventoryStatus, ListingStatus
from app.core.errors import ConflictError, ValidationFailedError
from app.core.money import ZERO
from app.models import (
    InventoryEvent,
    InventoryItem,
    Listing,
    ListingEvaluation,
    ListingStatusHistory,
    PredictionResult,
    Purchase,
)
from app.services import audit
from app.services.audit import Actor


@dataclass(frozen=True)
class PurchaseCosts:
    purchase_price: Decimal
    buyer_fee: Decimal = ZERO
    inbound_shipping: Decimal = ZERO
    other: Decimal = ZERO

    @property
    def total(self) -> Decimal:
        return self.purchase_price + self.buyer_fee + self.inbound_shipping + self.other

    def validate(self) -> None:
        if self.purchase_price <= 0:
            raise ValidationFailedError("the price paid must be positive")
        for name in ("buyer_fee", "inbound_shipping", "other"):
            if getattr(self, name) < 0:
                raise ValidationFailedError(f"{name.replace('_', ' ')} must not be negative")


def estimate_costs(price: Decimal, currency: str, fees: FeesConfig) -> PurchaseCosts:
    """Buyer fee and postage from your fee settings (only when they are in the same currency)."""
    if currency != fees.currency:
        return PurchaseCosts(purchase_price=price)
    channel = fees.purchase_channels[fees.default_purchase_channel]
    costs = acquisition_costs(price, channel, Extras())
    return PurchaseCosts(
        purchase_price=price,
        buyer_fee=costs.buyer_fee,
        inbound_shipping=costs.inbound_shipping,
    )


def with_total_paid(estimate: PurchaseCosts, total: Decimal) -> PurchaseCosts:
    """Checkout's actual total: the fee estimate is kept (capped) and postage is the rest."""
    price = estimate.purchase_price
    if total < price:
        raise ValidationFailedError("The total can't be less than the item price.")
    fee = min(estimate.buyer_fee, total - price)
    return PurchaseCosts(purchase_price=price, buyer_fee=fee, inbound_shipping=total - price - fee)


def existing_purchase_for_listing(session: Session, listing_id: int) -> Purchase | None:
    return session.scalars(
        select(Purchase).where(Purchase.listing_id == listing_id).order_by(Purchase.id).limit(1)
    ).first()


def record_purchase(
    session: Session,
    *,
    listing: Listing,
    costs: PurchaseCosts,
    currency: str,
    purchased_at: datetime,
    actor: Actor,
    evaluation: ListingEvaluation | None = None,
    alert_id: int | None = None,
    notes: str | None = None,
) -> tuple[Purchase, InventoryItem]:
    """Record a single-item purchase of a listing you bought yourself."""
    costs.validate()
    existing = existing_purchase_for_listing(session, listing.id)
    if existing is not None:
        raise ConflictError(f"purchase #{existing.id} is already recorded for this listing")

    total = costs.total
    purchase = Purchase(
        listing_id=listing.id,
        alert_id=alert_id,
        evaluation_id=evaluation.id if evaluation else None,
        marketplace=listing.marketplace,
        seller_id=listing.seller_id,
        purchased_at=purchased_at,
        currency=currency,
        purchase_price=costs.purchase_price,
        buyer_protection_fee=costs.buyer_fee,
        inbound_shipping=costs.inbound_shipping,
        other_acquisition_costs=costs.other,
        total_acquisition_cost=total,
        item_count=1,
        notes=notes,
        created_by_user_id=actor.user_id,
    )
    session.add(purchase)
    session.flush()

    expected_profit = _expected_profit(evaluation, total, currency)
    item = InventoryItem(
        purchase_id=purchase.id,
        listing_id=listing.id,
        product_id=(evaluation.product_id if evaluation else None) or listing.matched_product_id,
        brand_id=(evaluation.brand_id if evaluation else None) or listing.brand_id,
        category_id=(evaluation.category_id if evaluation else None) or listing.category_id,
        title=listing.title,
        size_normalised=listing.size_normalised,
        colour=listing.colour,
        currency=currency,
        allocated_acquisition_cost=total,
        expected_resale_price=evaluation.expected_sale_price if evaluation else None,
        expected_profit=expected_profit,
        status=InventoryStatus.ORDERED.value,
    )
    session.add(item)
    session.flush()
    session.add(
        InventoryEvent(
            inventory_item_id=item.id,
            from_status=None,
            to_status=InventoryStatus.ORDERED.value,
            occurred_at=purchased_at,
            note="purchase recorded",
            actor_user_id=actor.user_id,
        )
    )
    if evaluation is not None:
        session.add(_prediction(item, evaluation, expected_profit, total))

    if listing.status in (ListingStatus.ACTIVE.value, ListingStatus.RESERVED.value):
        # You bought it: the listing is gone. (Not a market observation - it sold to you.)
        session.add(
            ListingStatusHistory(
                listing_id=listing.id,
                from_status=listing.status,
                to_status=ListingStatus.SOLD.value,
                observed_at=purchased_at,
                note="bought by you",
            )
        )
        listing.status = ListingStatus.SOLD.value
        listing.status_changed_at = purchased_at

    audit.record(
        session, actor, action="purchase.create", entity_type="purchase", entity_id=purchase.id,
        after=audit.snapshot(purchase, [
            "listing_id", "currency", "purchase_price", "buyer_protection_fee",
            "inbound_shipping", "other_acquisition_costs", "total_acquisition_cost",
        ]),
    )  # fmt: skip
    session.flush()
    return purchase, item


def _expected_profit(
    evaluation: ListingEvaluation | None, total_cost: Decimal, currency: str
) -> Decimal | None:
    """Expected net proceeds at evaluation time minus what you actually paid."""
    if evaluation is None or evaluation.currency != currency:
        return None
    lines = (evaluation.details or {}).get("profit") or {}
    net = lines.get("net_proceeds")
    if net is None:
        return None
    return Decimal(str(net)) - total_cost


def _prediction(
    item: InventoryItem,
    evaluation: ListingEvaluation,
    expected_profit: Decimal | None,
    total_cost: Decimal,
) -> PredictionResult:
    roi = expected_profit / total_cost if expected_profit is not None and total_cost > 0 else None
    return PredictionResult(
        inventory_item_id=item.id,
        evaluation_id=evaluation.id,
        model_version=evaluation.pipeline_version,
        currency=item.currency,
        predicted_quick_sale=evaluation.quick_sale_price,
        predicted_expected_sale=evaluation.expected_sale_price,
        predicted_optimistic_sale=evaluation.optimistic_sale_price,
        predicted_profit=expected_profit,
        predicted_roi=roi.quantize(Decimal("0.0001")) if roi is not None else None,
        predicted_days_to_sale=evaluation.median_days_to_sale,
        predicted_comp_sample_size=evaluation.comp_sample_size,
        predicted_comp_level=evaluation.comp_level,
        predicted_from_price_guide=evaluation.estimate_basis == "price_guide",
    )
