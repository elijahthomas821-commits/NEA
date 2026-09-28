"""Load velocity evidence: sales per scope plus your unsold listed stock (censored)."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from app.analysis.market.comps import CompSale
from app.analysis.velocity.velocity import VelocityResult, VelocityScope, estimate_velocity
from app.config.schemas import VelocityRules
from app.core.enums import Condition, InventoryStatus, ListingStatus, PriceType, SaleSource
from app.core.time import age_days
from app.models import InventoryItem, Listing, MarketSale


def _sales(session: Session, *filters: ColumnElement[bool]) -> list[CompSale]:
    rows = session.scalars(
        select(MarketSale).where(
            MarketSale.excluded.is_(False), MarketSale.listed_at.is_not(None), *filters
        )
    )
    return [
        CompSale(
            id=r.id,
            product_id=r.product_id,
            brand_id=r.brand_id,
            category_id=r.category_id,
            size=r.size_normalised,
            condition=Condition(r.condition) if r.condition else None,
            price=r.sale_price,
            currency=r.currency,
            price_type=PriceType(r.price_type),
            source=SaleSource(r.source),
            marketplace=r.marketplace,
            sold_at=r.sold_at,
            listed_at=r.listed_at,
        )
        for r in rows
    ]


def _censored(session: Session, as_of: datetime, *filters: ColumnElement[bool]) -> list[Decimal]:
    rows = session.scalars(
        select(InventoryItem.listed_at).where(
            InventoryItem.status == InventoryStatus.LISTED.value,
            InventoryItem.listed_at.is_not(None),
            *filters,
        )
    )
    return [Decimal(str(round(age_days(listed_at, as_of), 1))) for listed_at in rows if listed_at]


def _active(session: Session, *filters: ColumnElement[bool]) -> int:
    return int(
        session.scalar(
            select(func.count(Listing.id)).where(
                Listing.status == ListingStatus.ACTIVE.value, *filters
            )
        )
        or 0
    )


def velocity_for(
    session: Session,
    *,
    brand_id: int,
    category_id: int,
    product_id: int | None,
    product_is_generic: bool,
    as_of: datetime,
    rules: VelocityRules,
) -> VelocityResult:
    scopes: list[VelocityScope] = []
    if product_id is not None and not product_is_generic:
        scopes.append(
            VelocityScope(
                name="product",
                sales=_sales(session, MarketSale.product_id == product_id),
                censored_days=_censored(session, as_of, InventoryItem.product_id == product_id),
                active_observed=_active(session, Listing.matched_product_id == product_id),
            )
        )
    scopes.append(
        VelocityScope(
            name="brand+category",
            sales=_sales(
                session, MarketSale.brand_id == brand_id, MarketSale.category_id == category_id
            ),
            censored_days=_censored(
                session,
                as_of,
                InventoryItem.brand_id == brand_id,
                InventoryItem.category_id == category_id,
            ),
            active_observed=_active(
                session, Listing.brand_id == brand_id, Listing.category_id == category_id
            ),
        )
    )
    scopes.append(
        VelocityScope(
            name="category",
            sales=_sales(session, MarketSale.category_id == category_id),
            censored_days=_censored(session, as_of, InventoryItem.category_id == category_id),
            active_observed=_active(session, Listing.category_id == category_id),
        )
    )
    return estimate_velocity(scopes, as_of=as_of, rules=rules)
