"""Price a target (a listing, or a what-if query): comparable sales first, price guide second."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy.orm import Session

from app.analysis.identification.types import Catalogue
from app.analysis.market.comps import CompTarget, MarketResult, estimate_market
from app.analysis.pricing.estimates import (
    PriceEstimate,
    estimate_from_guide,
    estimate_from_market,
)
from app.core.enums import Condition, ProductLevel
from app.models import Product
from app.services.config_service import ConfigBundle
from app.services.market_data import load_comps, load_fx


@dataclass(frozen=True)
class PricingOutcome:
    market: MarketResult
    estimate: PriceEstimate | None

    @property
    def used_price_guide(self) -> bool:
        return self.estimate is not None and self.estimate.basis == "price_guide"


def price_target(
    session: Session,
    bundle: ConfigBundle,
    catalogue: Catalogue,
    *,
    brand_id: int,
    category_id: int,
    product_id: int | None,
    size: str | None,
    colour: str | None,
    condition: Condition | None,
    currency: str,
    match_confidence: Decimal,
    as_of: datetime,
) -> PricingOutcome:
    product = session.get(Product, product_id) if product_id is not None else None
    is_generic = product is None or product.level == ProductLevel.BRAND_CATEGORY_GENERIC.value
    category = catalogue.category_by_id(category_id)
    brand = catalogue.brand_by_id(brand_id)
    target = CompTarget(
        product_id=product_id,
        product_is_generic=is_generic,
        brand_id=brand_id,
        category_id=category_id,
        category_slug=category.slug if category else None,
        size=size,
        colour=colour,
        condition=condition,
        currency=currency,
        match_confidence=match_confidence,
        as_of=as_of,
    )
    market = estimate_market(
        target,
        load_comps(
            session,
            brand_id=brand_id,
            category_id=category_id,
            since=as_of - timedelta(days=bundle.market.window_days),
            until=as_of,
        ),
        market=bundle.market,
        conditions=bundle.conditions,
        sizes=bundle.sizes,
        fx=load_fx(session),
    )
    estimate = estimate_from_market(market, bundle.market.estimate_percentiles)
    if estimate is None:
        estimate = estimate_from_guide(
            bundle.price_guide,
            bundle.market.price_guide,
            brand_slug=brand.slug if brand else None,
            category_slug=category.slug if category else None,
            product_slug=None if is_generic or product is None else product.slug,
            condition=condition,
            size=size,
            currency=currency,
            conditions=bundle.conditions,
            sizes=bundle.sizes,
        )
    return PricingOutcome(market=market, estimate=estimate)
