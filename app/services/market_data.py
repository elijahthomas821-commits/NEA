"""Market data: recording comparable sales, loading them for pricing, FX rates.

You have no sales history yet, so comps come from:

* sales you research by hand (``manual_entry``, CSV import) — e.g. sold listings you can see;
* your own completed resales (``own_sale``), recorded automatically when you sell;
* listings you watched that went "sold" (``observed_sold_listing``; last asking price only).

Each comp is resolved to the catalogue (brand, category, product), normalised (size, condition,
colour) and protected against double entry.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.analysis.identification.rules import identify
from app.analysis.identification.types import Catalogue, ListingText
from app.analysis.market.comps import CompSale, FxTable
from app.analysis.matching.matcher import match_product
from app.analysis.normalisation.colour import find_colour, normalise_colour_field
from app.analysis.normalisation.condition import match_condition, match_condition_label
from app.analysis.normalisation.size import find_size_in_text, parse_size_value
from app.collectors.base import RawSale
from app.config.schemas import IdentificationConfig, SizesConfig
from app.core.enums import Condition, PriceType, ProductLevel, SaleSource
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.money import normalise_currency
from app.core.time import days_between
from app.models import Brand, Category, FxRate, Listing, Marketplace, MarketSale, Product
from app.services import audit
from app.services.audit import Actor
from app.services.catalogue import load_products, resolve_brand, resolve_category


def _condition(raw: str | None, title: str | None) -> Condition | None:
    if raw:
        label = match_condition_label(raw)
        if label is not None:
            return label
        match = match_condition(raw, "field")
        if match is not None:
            return match.condition
    match = match_condition(title, "title")
    return match.condition if match else None


def _source_ref(raw: RawSale, brand_id: int, category_id: int) -> str:
    """Deterministic reference for entries without one, so the same comp can't be typed twice."""
    payload = {
        "brand": brand_id,
        "category": category_id,
        "product": raw.product,
        "title": (raw.title or "").strip().lower(),
        "size": raw.size,
        "condition": raw.condition,
        "price": str(raw.sale_price),
        "currency": raw.currency,
        "sold_on": raw.sold_at.date().isoformat(),
        "marketplace": raw.marketplace,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return f"auto:{digest[:32]}"


def resolve_product(
    session: Session,
    raw: RawSale,
    catalogue: Catalogue,
    brand_id: int,
    category_id: int,
    identification: IdentificationConfig,
    sizes: SizesConfig,
) -> tuple[int, Decimal]:
    """(product_id, match_confidence). Falls back to the brand x category "any model" product."""
    products = [p for p in load_products(session, [brand_id]) if p.category_id == category_id]
    if raw.product:
        wanted = raw.product.strip().lower()
        for product_row in session.scalars(
            select(Product).where(Product.brand_id == brand_id, Product.category_id == category_id)
        ):
            if wanted in (product_row.slug, product_row.canonical_name.lower()):
                return product_row.id, Decimal(1)
        raise ValidationFailedError(f"unknown product {raw.product!r} for this brand and category")
    if raw.title:
        brand = catalogue.brand_by_id(brand_id)
        category = catalogue.category_by_id(category_id)
        ident = identify(
            ListingText(
                title=raw.title,
                raw_brand=brand.name if brand else None,
                raw_category=category.name if category else None,
            ),
            catalogue,
            identification,
            sizes,
        )
        ident = ident.model_copy(
            update={
                "brand_id": brand_id,
                "category_id": category_id,
                "category_confidence": max(ident.category_confidence, Decimal("0.9")),
            }
        )
        match = match_product(ident, products, identification.matching)
        if match.product_id is not None and match.method in ("alias", "model_code", "fuzzy"):
            return match.product_id, max(min(match.confidence, Decimal(1)), Decimal("0.5"))
    generic = next((p for p in products if p.level == ProductLevel.BRAND_CATEGORY_GENERIC), None)
    if generic is None:
        raise ValidationFailedError(
            "this category is not in scope: comps are only recorded for in-scope categories"
        )
    return generic.id, Decimal(1)


def record_sale(
    session: Session,
    raw: RawSale,
    *,
    catalogue: Catalogue,
    identification: IdentificationConfig,
    sizes: SizesConfig,
    actor: Actor,
    inventory_item_id: int | None = None,
    listing_id: int | None = None,
) -> tuple[MarketSale, bool]:
    """Store one comparable sale. Returns ``(row, created)``; duplicates are not re-inserted."""
    brand = resolve_brand(catalogue, raw.brand)
    if brand is None:
        raise ValidationFailedError(
            f"unknown brand {raw.brand!r}: add it to the catalogue first (POST /brands)"
        )
    category = resolve_category(catalogue, raw.category)
    if category is None:
        raise ValidationFailedError(f"unknown category {raw.category!r}")
    if raw.marketplace and session.get(Marketplace, raw.marketplace) is None:
        raise ValidationFailedError(f"unknown marketplace {raw.marketplace!r}")

    product_id, match_confidence = resolve_product(
        session, raw, catalogue, brand.id, category.id, identification, sizes
    )
    size = parse_size_value(raw.size, brand_slug=brand.slug, config=sizes)
    if not size.known and raw.title:
        size = find_size_in_text(raw.title, brand_slug=brand.slug, config=sizes, source="title")
    condition = _condition(raw.condition, raw.title)
    colour = normalise_colour_field(raw.colour) or find_colour(raw.title)
    source_ref = raw.source_ref or _source_ref(raw, brand.id, category.id)
    days_to_sale = days_between(raw.listed_at, raw.sold_at) if raw.listed_at else None

    stmt = (
        pg_insert(MarketSale)
        .values(
            source=raw.source.value,
            source_ref=source_ref,
            marketplace=raw.marketplace,
            listing_id=listing_id,
            inventory_item_id=inventory_item_id,
            product_id=product_id,
            brand_id=brand.id,
            category_id=category.id,
            title=raw.title,
            size_normalised=size.normalised,
            colour=colour,
            condition=condition.value if condition else None,
            sale_price=raw.sale_price,
            currency=raw.currency,
            price_type=raw.price_type.value,
            listed_at=raw.listed_at,
            sold_at=raw.sold_at,
            days_to_sale=days_to_sale,
            match_confidence=match_confidence,
            notes=raw.notes,
            raw=raw.model_dump(mode="json", exclude_none=True),
            created_by_user_id=actor.user_id,
        )
        .on_conflict_do_nothing(index_elements=["source", "source_ref"])
        .returning(MarketSale.id)
    )
    new_id = session.execute(stmt).scalar_one_or_none()
    if new_id is None:
        existing = session.scalar(
            select(MarketSale).where(
                MarketSale.source == raw.source.value, MarketSale.source_ref == source_ref
            )
        )
        assert existing is not None
        return existing, False
    row = session.get(MarketSale, new_id)
    assert row is not None
    audit.record(
        session, actor, action="market_sale.create", entity_type="market_sale", entity_id=new_id,
        after={"price": str(raw.sale_price), "currency": raw.currency, "source": raw.source.value},
    )  # fmt: skip
    return row, True


def observe_sold_listing(
    session: Session,
    listing: Listing,
    *,
    sold_at: datetime,
    catalogue: Catalogue,
    identification: IdentificationConfig,
    sizes: SizesConfig,
    actor: Actor,
) -> MarketSale | None:
    """A listing you were watching sold to someone else: its last asking price becomes a comp.

    It is stored as ``last_asking_price``, so pricing applies the configured haircut and lower
    trust (the final price may have been negotiated down). Nothing is recorded when the listing
    has no price, or was never identified to a catalogue brand and an in-scope category.
    """
    if listing.price is None or listing.currency is None:
        return None
    brand = session.get(Brand, listing.brand_id) if listing.brand_id else None
    category = session.get(Category, listing.category_id) if listing.category_id else None
    if brand is None or category is None:
        return None
    listed_at = min(listing.listed_at or listing.first_seen_at, sold_at)
    raw = RawSale(
        source=SaleSource.OBSERVED_SOLD_LISTING,
        source_ref=f"listing:{listing.id}",
        marketplace=listing.marketplace,
        title=listing.title[:300],
        brand=brand.slug,
        category=category.slug,
        size=listing.size_normalised,
        colour=listing.colour,
        condition=listing.condition,
        sale_price=listing.price,
        currency=listing.currency,
        price_type=PriceType.LAST_ASKING_PRICE,
        listed_at=listed_at,
        sold_at=sold_at,
        notes="last asking price of a listing that sold",
    )
    try:
        row, _ = record_sale(
            session, raw, catalogue=catalogue, identification=identification, sizes=sizes,
            actor=actor, listing_id=listing.id,
        )  # fmt: skip
    except ValidationFailedError:
        return None
    return row


def record_sale_with_active_config(
    session: Session,
    raw: RawSale,
    *,
    actor: Actor,
    inventory_item_id: int | None = None,
    listing_id: int | None = None,
) -> tuple[MarketSale, bool]:
    """:func:`record_sale` with the active catalogue and configuration."""
    from app.services.catalogue import load_catalogue
    from app.services.config_service import ConfigService

    bundle = ConfigService(session).bundle()
    return record_sale(
        session, raw, catalogue=load_catalogue(session), identification=bundle.identification,
        sizes=bundle.sizes, actor=actor, inventory_item_id=inventory_item_id,
        listing_id=listing_id,
    )  # fmt: skip


def record_sold_observation(
    session: Session, listing: Listing, *, sold_at: datetime, actor: Actor
) -> MarketSale | None:
    """:func:`observe_sold_listing` with the active catalogue and configuration."""
    from app.services.catalogue import load_catalogue
    from app.services.config_service import ConfigService

    bundle = ConfigService(session).bundle()
    return observe_sold_listing(
        session, listing, sold_at=sold_at, catalogue=load_catalogue(session),
        identification=bundle.identification, sizes=bundle.sizes, actor=actor,
    )  # fmt: skip


def set_excluded(
    session: Session, sale_id: int, *, excluded: bool, reason: str | None, actor: Actor
) -> MarketSale:
    row = session.get(MarketSale, sale_id)
    if row is None:
        raise NotFoundError(f"market sale {sale_id} not found")
    before = {"excluded": row.excluded, "reason": row.excluded_reason}
    row.excluded = excluded
    row.excluded_reason = reason if excluded else None
    audit.record(
        session, actor, action="market_sale.exclude" if excluded else "market_sale.restore",
        entity_type="market_sale", entity_id=sale_id, before=before,
        after={"excluded": excluded, "reason": reason},
    )  # fmt: skip
    return row


def load_comps(session: Session, *, brand_id: int, category_id: int) -> list[CompSale]:
    """All usable sales for a brand x category (the engine applies window and level rules)."""
    rows = session.scalars(
        select(MarketSale).where(
            MarketSale.brand_id == brand_id,
            MarketSale.category_id == category_id,
            MarketSale.excluded.is_(False),
        )
    )
    return [
        CompSale(
            id=row.id,
            product_id=row.product_id,
            brand_id=row.brand_id,
            category_id=row.category_id,
            size=row.size_normalised,
            colour=row.colour,
            condition=Condition(row.condition) if row.condition else None,
            price=row.sale_price,
            currency=row.currency,
            price_type=PriceType(row.price_type),
            source=SaleSource(row.source),
            marketplace=row.marketplace,
            sold_at=row.sold_at,
            listed_at=row.listed_at,
            trust_weight=row.trust_weight,
            match_confidence=row.match_confidence,
        )
        for row in rows
    ]


def load_fx(session: Session) -> FxTable:
    rates: dict[str, list[tuple[date, Decimal]]] = {}
    for row in session.scalars(select(FxRate)):
        rates.setdefault(FxTable.key(row.base, row.quote), []).append((row.as_of, row.rate))
    return FxTable(rates=rates)


def add_fx_rate(
    session: Session, *, base: str, quote: str, rate: Decimal, as_of: date, actor: Actor
) -> FxRate:
    base, quote = normalise_currency(base), normalise_currency(quote)
    if base == quote:
        raise ValidationFailedError("base and quote currencies must differ")
    if rate <= 0:
        raise ValidationFailedError("rate must be positive")
    stmt = (
        pg_insert(FxRate)
        .values(base=base, quote=quote, rate=rate, as_of=as_of, source="manual")
        .on_conflict_do_update(
            index_elements=["base", "quote", "as_of"], set_={"rate": rate, "source": "manual"}
        )
        .returning(FxRate.id)
    )
    row_id = session.execute(stmt).scalar_one()
    row = session.get(FxRate, row_id)
    assert row is not None
    session.refresh(row)
    audit.record(
        session, actor, action="fx_rate.set", entity_type="fx_rate", entity_id=row_id,
        after={"pair": f"{base}/{quote}", "rate": str(rate), "as_of": as_of.isoformat()},
    )  # fmt: skip
    return row


def sale_to_dict(row: MarketSale) -> dict[str, object]:
    return {
        "id": row.id,
        "source": row.source,
        "source_ref": row.source_ref,
        "marketplace": row.marketplace,
        "brand_id": row.brand_id,
        "category_id": row.category_id,
        "product_id": row.product_id,
        "title": row.title,
        "size": row.size_normalised,
        "colour": row.colour,
        "condition": row.condition,
        "sale_price": row.sale_price,
        "currency": row.currency,
        "price_type": row.price_type,
        "listed_at": row.listed_at,
        "sold_at": row.sold_at,
        "days_to_sale": row.days_to_sale,
        "match_confidence": row.match_confidence,
        "excluded": row.excluded,
        "excluded_reason": row.excluded_reason,
    }
