"""Recording purchases you made yourself.

The system never buys anything. After you buy on the marketplace, you record what you actually
paid; that creates the purchase, one inventory item per item bought (status ``ordered``) and a
snapshot of what each evaluation predicted, so predictions can be checked against the real
outcome once the items sell.

Bundles (several items bought together) split the total cost across the items: in proportion to
their expected resale prices (default), equally, or by amounts you give. The split is exact to
the penny (see :mod:`app.analysis.profit.allocation`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.profit.allocation import allocate
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
    """The purchase that already includes this listing, if you bought it before."""
    return session.scalars(
        select(Purchase)
        .join(InventoryItem, InventoryItem.purchase_id == Purchase.id)
        .where(InventoryItem.listing_id == listing_id)
        .order_by(Purchase.id)
        .limit(1)
    ).first()


Allocation = Literal["expected_value", "equal", "manual"]


@dataclass(frozen=True)
class PurchaseItem:
    """One item of a purchase: a listing you evaluated, or an item described by hand."""

    listing: Listing | None = None
    evaluation: ListingEvaluation | None = None
    title: str | None = None
    brand_id: int | None = None
    category_id: int | None = None
    product_id: int | None = None
    size: str | None = None
    colour: str | None = None
    expected_resale_price: Decimal | None = None  # defaults to the evaluation's estimate
    allocated_cost: Decimal | None = None  # "manual" allocation only

    @property
    def expected(self) -> Decimal | None:
        if self.expected_resale_price is not None:
            return self.expected_resale_price
        return self.evaluation.expected_sale_price if self.evaluation else None


def allocate_costs(
    items: list[PurchaseItem], total: Decimal, allocation: Allocation
) -> list[Decimal]:
    if len(items) == 1:
        return [total]
    if allocation == "manual":
        shares = [i.allocated_cost for i in items]
        if any(s is None or s < 0 for s in shares):
            raise ValidationFailedError("manual allocation needs a cost for every item")
        given = [s for s in shares if s is not None]
        if sum(given, ZERO) != total:
            raise ValidationFailedError(
                f"the item costs add up to {sum(given, ZERO)}, not the total {total}"
            )
        return given
    if allocation == "equal":
        return allocate(total, [Decimal(1)] * len(items))
    weights = [i.expected for i in items]
    if any(w is None for w in weights):
        raise ValidationFailedError(
            "splitting by expected value needs an expected resale price for every item "
            "(evaluate the listings, give expected_resale_price, or use equal/manual)"
        )
    return allocate(total, [w for w in weights if w is not None])


def record_purchase_items(
    session: Session,
    *,
    items: list[PurchaseItem],
    costs: PurchaseCosts,
    currency: str,
    marketplace: str,
    purchased_at: datetime,
    actor: Actor,
    allocation: Allocation = "expected_value",
    alert_id: int | None = None,
    notes: str | None = None,
) -> tuple[Purchase, list[InventoryItem]]:
    """Record a purchase of one or more items (a bundle)."""
    costs.validate()
    if not items:
        raise ValidationFailedError("a purchase needs at least one item")
    listing_ids = [i.listing.id for i in items if i.listing is not None]
    if len(listing_ids) != len(set(listing_ids)):
        raise ValidationFailedError("the same listing appears twice")
    for listing_id in listing_ids:
        existing = existing_purchase_for_listing(session, listing_id)
        if existing is not None:
            raise ConflictError(
                f"purchase #{existing.id} is already recorded for listing #{listing_id}"
            )
    for item in items:
        if item.listing is None and not (item.title and item.title.strip()):
            raise ValidationFailedError("an item without a listing needs a title")

    total = costs.total
    shares = allocate_costs(items, total, allocation)
    first_listing = next((i.listing for i in items if i.listing is not None), None)
    purchase = Purchase(
        listing_id=first_listing.id if first_listing else None,
        alert_id=alert_id,
        evaluation_id=items[0].evaluation.id if len(items) == 1 and items[0].evaluation else None,
        marketplace=first_listing.marketplace if first_listing else marketplace,
        seller_id=first_listing.seller_id if first_listing else None,
        purchased_at=purchased_at,
        currency=currency,
        purchase_price=costs.purchase_price,
        buyer_protection_fee=costs.buyer_fee,
        inbound_shipping=costs.inbound_shipping,
        other_acquisition_costs=costs.other,
        total_acquisition_cost=total,
        item_count=len(items),
        notes=notes,
        created_by_user_id=actor.user_id,
    )
    session.add(purchase)
    session.flush()

    created = [
        _create_item(session, purchase, spec, share, currency, actor)
        for spec, share in zip(items, shares, strict=True)
    ]
    audit.record(
        session, actor, action="purchase.create", entity_type="purchase", entity_id=purchase.id,
        after={
            **audit.snapshot(purchase, [
                "currency", "purchase_price", "buyer_protection_fee", "inbound_shipping",
                "other_acquisition_costs", "total_acquisition_cost", "item_count",
            ]),
            "allocation": allocation if len(items) > 1 else None,
            "items": [
                {"inventory_item_id": i.id, "listing_id": i.listing_id,
                 "allocated_cost": str(i.allocated_acquisition_cost)}
                for i in created
            ],
        },
    )  # fmt: skip
    session.flush()
    return purchase, created


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
    purchase, items = record_purchase_items(
        session,
        items=[PurchaseItem(listing=listing, evaluation=evaluation)],
        costs=costs,
        currency=currency,
        marketplace=listing.marketplace,
        purchased_at=purchased_at,
        actor=actor,
        alert_id=alert_id,
        notes=notes,
    )
    return purchase, items[0]


def _create_item(
    session: Session,
    purchase: Purchase,
    spec: PurchaseItem,
    share: Decimal,
    currency: str,
    actor: Actor,
) -> InventoryItem:
    listing, evaluation = spec.listing, spec.evaluation
    expected_profit = _expected_profit(evaluation, share, currency)
    item = InventoryItem(
        purchase_id=purchase.id,
        listing_id=listing.id if listing else None,
        product_id=spec.product_id
        or (evaluation.product_id if evaluation else None)
        or (listing.matched_product_id if listing else None),
        brand_id=spec.brand_id
        or (evaluation.brand_id if evaluation else None)
        or (listing.brand_id if listing else None),
        category_id=spec.category_id
        or (evaluation.category_id if evaluation else None)
        or (listing.category_id if listing else None),
        title=(spec.title or (listing.title if listing else ""))[:300],
        size_normalised=spec.size or (listing.size_normalised if listing else None),
        colour=spec.colour or (listing.colour if listing else None),
        currency=currency,
        allocated_acquisition_cost=share,
        expected_resale_price=spec.expected,
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
            occurred_at=purchase.purchased_at,
            note="purchase recorded",
            actor_user_id=actor.user_id,
        )
    )
    if evaluation is not None:
        session.add(_prediction(item, evaluation, expected_profit, share))
    if listing is not None and listing.status in (
        ListingStatus.ACTIVE.value,
        ListingStatus.RESERVED.value,
    ):
        # You bought it: the listing is gone. (Not a market observation - it sold to you.)
        session.add(
            ListingStatusHistory(
                listing_id=listing.id,
                from_status=listing.status,
                to_status=ListingStatus.SOLD.value,
                observed_at=purchase.purchased_at,
                note="bought by you",
            )
        )
        listing.status = ListingStatus.SOLD.value
        listing.status_changed_at = purchase.purchased_at
    return item


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
