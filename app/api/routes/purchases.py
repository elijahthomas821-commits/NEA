"""Purchases you made yourself (the system never buys anything)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.analysis.normalisation.colour import normalise_colour_field
from app.analysis.normalisation.size import parse_size_value
from app.api.deps import PrincipalDep, SessionDep, SettingsDep
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.time import utcnow
from app.models import Listing, ListingEvaluation, Marketplace, Purchase
from app.schemas.inventory import InventoryItemOut, PurchaseIn, PurchaseOut
from app.services.alerts import latest_evaluation
from app.services.catalogue import load_catalogue, resolve_brand, resolve_category
from app.services.config_service import ConfigService
from app.services.purchases import (
    PurchaseCosts,
    PurchaseItem,
    estimate_costs,
    record_purchase_items,
)

router = APIRouter(prefix="/purchases", tags=["purchases"])


def _out(purchase: Purchase) -> PurchaseOut:
    return PurchaseOut(
        **{name: getattr(purchase, name) for name in PurchaseOut.model_fields if name != "items"},
        items=[
            InventoryItemOut.model_validate(i) for i in sorted(purchase.items, key=lambda i: i.id)
        ],
    )


@router.post("", response_model=PurchaseOut, status_code=201)
def create_purchase(
    body: PurchaseIn, principal: PrincipalDep, session: SessionDep, settings: SettingsDep
) -> PurchaseOut:
    """Record what you paid for one item or a bundle.

    Fees and postage you leave out are estimated from your fee settings. A bundle's total cost
    is split across its items by expected resale value (default), equally, or as you specify.
    """
    bundle = ConfigService(session).bundle()
    fees = bundle.fees
    catalogue = load_catalogue(session)
    items: list[PurchaseItem] = []
    for spec in body.items:
        listing = evaluation = None
        if spec.listing_id is not None:
            listing = session.get(Listing, spec.listing_id)
            if listing is None:
                raise NotFoundError(f"listing {spec.listing_id} not found")
        if spec.evaluation_id is not None:
            evaluation = session.get(ListingEvaluation, spec.evaluation_id)
            if evaluation is None or (listing and evaluation.listing_id != listing.id):
                raise ValidationFailedError(f"evaluation {spec.evaluation_id} is not for this item")
        elif listing is not None:
            evaluation = latest_evaluation(session, listing.id)
        brand = resolve_brand(catalogue, spec.brand) if spec.brand else None
        if spec.brand and brand is None:
            raise ValidationFailedError(f"unknown brand {spec.brand!r}")
        category = resolve_category(catalogue, spec.category) if spec.category else None
        if spec.category and category is None:
            raise ValidationFailedError(f"unknown category {spec.category!r}")
        items.append(
            PurchaseItem(
                listing=listing,
                evaluation=evaluation,
                title=spec.title,
                brand_id=brand.id if brand else None,
                category_id=category.id if category else None,
                size=parse_size_value(
                    spec.size, brand_slug=brand.slug if brand else None, config=bundle.sizes
                ).normalised,
                colour=normalise_colour_field(spec.colour),
                expected_resale_price=spec.expected_resale_price,
                allocated_cost=spec.allocated_cost,
            )
        )

    first_listing = next((i.listing for i in items if i.listing is not None), None)
    currency = body.currency or (first_listing.currency if first_listing else None)
    currency = currency or settings.base_currency
    if session.get(Marketplace, body.marketplace) is None:
        raise ValidationFailedError(f"unknown marketplace {body.marketplace!r}")
    estimate = estimate_costs(body.purchase_price, currency, fees)
    costs = PurchaseCosts(
        purchase_price=body.purchase_price,
        buyer_fee=(
            body.buyer_protection_fee
            if body.buyer_protection_fee is not None
            else estimate.buyer_fee
        ),
        inbound_shipping=(
            body.inbound_shipping
            if body.inbound_shipping is not None
            else estimate.inbound_shipping
        ),
        other=body.other_acquisition_costs,
    )
    purchase, _ = record_purchase_items(
        session,
        items=items,
        costs=costs,
        currency=currency,
        marketplace=body.marketplace,
        purchased_at=body.purchased_at or utcnow(),
        actor=principal.actor,
        allocation=body.allocation,
        alert_id=body.alert_id,
        notes=body.notes,
    )
    session.commit()
    session.expire_all()  # answer with the stored values (110 → 110.00), exactly as GET does
    return _out(purchase)


@router.get("")
def list_purchases(
    principal: PrincipalDep,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    total = session.scalar(select(func.count(Purchase.id))) or 0
    rows = session.scalars(
        select(Purchase).order_by(Purchase.purchased_at.desc(), Purchase.id.desc())
        .limit(limit).offset(offset)
    )  # fmt: skip
    return {"items": [_out(p) for p in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/{purchase_id}", response_model=PurchaseOut)
def get_purchase(purchase_id: int, principal: PrincipalDep, session: SessionDep) -> PurchaseOut:
    purchase = session.get(Purchase, purchase_id)
    if purchase is None:
        raise NotFoundError(f"purchase {purchase_id} not found")
    return _out(purchase)
