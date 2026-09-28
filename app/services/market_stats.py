"""Nightly market statistics snapshot (for reporting; evaluations always recompute live)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.analysis.market.comps import STANDARD_PERCENTILES
from app.analysis.market.stats import (
    effective_sample_size,
    median,
    recency_weight,
    weighted_percentile,
)
from app.config.schemas import MarketConfig
from app.core.enums import CompLevel, ListingStatus, PriceType, ProductLevel, SaleSource
from app.core.time import age_days
from app.models import Listing, MarketSale, MarketStatistic, Product

METHOD_VERSION = "1"


def _weight(row: MarketSale, now: datetime, cfg: MarketConfig) -> Decimal:
    trust = cfg.source_trust.get(SaleSource(row.source), Decimal("0.5"))
    trust *= cfg.marketplace_trust.get(
        row.marketplace or "default", cfg.marketplace_trust["default"]
    )
    if row.price_type == PriceType.LAST_ASKING_PRICE.value:
        trust *= cfg.last_asking_price.trust_multiplier
    age = Decimal(str(age_days(row.sold_at, now)))
    return recency_weight(age, cfg.half_life_days) * trust * row.match_confidence


def _price(row: MarketSale, cfg: MarketConfig) -> Decimal:
    if row.price_type == PriceType.LAST_ASKING_PRICE.value:
        return row.sale_price * cfg.last_asking_price.haircut
    return row.sale_price


def _stats_row(
    rows: list[MarketSale],
    *,
    scope_level: CompLevel,
    now: datetime,
    cfg: MarketConfig,
    currency: str,
    active_observed: int,
    product_id: int | None = None,
    brand_id: int | None = None,
    category_id: int | None = None,
) -> MarketStatistic:
    pairs = [(_price(r, cfg), _weight(r, now, cfg)) for r in rows]
    pairs = [p for p in pairs if p[1] > 0]
    percentiles = (
        {
            name: weighted_percentile(pairs, q).quantize(Decimal("0.01"))
            for name, q in STANDARD_PERCENTILES.items()
        }
        if pairs
        else {}
    )
    days = [Decimal(r.days_to_sale) for r in rows if r.days_to_sale is not None]
    return MarketStatistic(
        scope_level=scope_level.value,
        product_id=product_id,
        brand_id=brand_id,
        category_id=category_id,
        window_days=cfg.window_days,
        currency=currency,
        sample_size=len(rows),
        effective_sample_size=effective_sample_size([w for _, w in pairs]).quantize(
            Decimal("0.01")
        ),
        p10=percentiles.get("p10"),
        p25=percentiles.get("p25"),
        median=percentiles.get("p50"),
        p75=percentiles.get("p75"),
        p90=percentiles.get("p90"),
        median_days_to_sale=median(days).quantize(Decimal("0.1")) if days else None,
        sales_last_30d=sum(1 for r in rows if r.sold_at >= now - timedelta(days=30)),
        sales_last_90d=sum(1 for r in rows if r.sold_at >= now - timedelta(days=90)),
        active_listings_observed=active_observed,
        method_version=METHOD_VERSION,
        computed_at=now,
    )


def _usable(rows: Iterable[MarketSale], cfg: MarketConfig) -> list[MarketSale]:
    return [
        r
        for r in rows
        if r.price_type == PriceType.FINAL_SALE_PRICE.value or cfg.last_asking_price.use_for_price
    ]


def recompute_market_statistics(
    session: Session, *, now: datetime, cfg: MarketConfig, currency: str
) -> int:
    """Replace the snapshot: one row per product (L4) and per brand x category (L6)."""
    session.execute(delete(MarketStatistic))
    rows = list(
        session.scalars(
            select(MarketSale).where(
                MarketSale.excluded.is_(False),
                MarketSale.currency == currency,
                MarketSale.sold_at <= now,
                MarketSale.sold_at >= now - timedelta(days=cfg.window_days),
            )
        )
    )
    generic_ids = set(
        session.scalars(
            select(Product.id).where(Product.level == ProductLevel.BRAND_CATEGORY_GENERIC.value)
        )
    )
    active = ListingStatus.ACTIVE.value
    active_by_product = dict(
        session.execute(
            select(Listing.matched_product_id, func.count())
            .where(Listing.status == active, Listing.matched_product_id.is_not(None))
            .group_by(Listing.matched_product_id)
        ).all()
    )
    active_by_scope = {
        (b, c): n
        for b, c, n in session.execute(
            select(Listing.brand_id, Listing.category_id, func.count())
            .where(Listing.status == active)
            .group_by(Listing.brand_id, Listing.category_id)
        ).all()
    }

    by_product: dict[int, list[MarketSale]] = defaultdict(list)
    by_scope: dict[tuple[int, int], list[MarketSale]] = defaultdict(list)
    for row in _usable(rows, cfg):
        if row.product_id is not None and row.product_id not in generic_ids:
            by_product[row.product_id].append(row)
        by_scope[(row.brand_id, row.category_id)].append(row)

    created = 0
    for product_id, group in by_product.items():
        session.add(
            _stats_row(
                group, scope_level=CompLevel.L4, now=now, cfg=cfg, currency=currency,
                active_observed=active_by_product.get(product_id, 0), product_id=product_id,
                brand_id=group[0].brand_id, category_id=group[0].category_id,
            )
        )  # fmt: skip
        created += 1
    for (brand_id, category_id), group in by_scope.items():
        session.add(
            _stats_row(
                group, scope_level=CompLevel.L6, now=now, cfg=cfg, currency=currency,
                active_observed=active_by_scope.get((brand_id, category_id), 0),
                brand_id=brand_id, category_id=category_id,
            )
        )  # fmt: skip
        created += 1
    session.flush()
    return created
