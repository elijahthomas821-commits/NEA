"""Load velocity evidence: sales per scope plus your unsold listed stock (censored)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from app.analysis.market.comps import CompSale
from app.analysis.velocity.velocity import VelocityResult, VelocityScope, estimate_velocity
from app.config.schemas import VelocityRules
from app.core.enums import InventoryStatus, ListingStatus
from app.core.time import age_days
from app.models import InventoryItem, Listing, MarketSale
from app.services.market_data import COMP_COLUMNS, comp_from_row


def _sales(
    session: Session, window: tuple[datetime, datetime], *filters: ColumnElement[bool]
) -> list[CompSale]:
    since, until = window
    rows = session.execute(
        select(*COMP_COLUMNS).where(
            MarketSale.excluded.is_(False),
            MarketSale.listed_at.is_not(None),
            MarketSale.sold_at >= since,
            MarketSale.sold_at <= until,
            *filters,
        )
    )
    return [comp_from_row(row) for row in rows]


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
    window_days: int = 365,
) -> VelocityResult:
    """Sale speed from sales in the last ``window_days`` (up to ``as_of``) plus unsold stock.

    Scopes go from specific to broad and the first with enough sales is used, so broader
    scopes are only loaded when the narrower ones fall short.
    """
    window = (as_of - timedelta(days=window_days), as_of)
    builders: list[Callable[[], VelocityScope]] = []
    if product_id is not None and not product_is_generic:
        builders.append(
            lambda: VelocityScope(
                name="product",
                sales=_sales(session, window, MarketSale.product_id == product_id),
                censored_days=_censored(session, as_of, InventoryItem.product_id == product_id),
                active_observed=_active(session, Listing.matched_product_id == product_id),
            )
        )
    builders.append(
        lambda: VelocityScope(
            name="brand+category",
            sales=_sales(
                session,
                window,
                MarketSale.brand_id == brand_id,
                MarketSale.category_id == category_id,
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
    builders.append(
        lambda: VelocityScope(
            name="category",
            sales=_sales(session, window, MarketSale.category_id == category_id),
            censored_days=_censored(session, as_of, InventoryItem.category_id == category_id),
            active_observed=_active(session, Listing.category_id == category_id),
        )
    )
    for build in builders:
        result = estimate_velocity([build()], as_of=as_of, rules=rules)
        if result.scope is not None:
            return result
    return VelocityResult()
