"""Catalogue access (brands, categories, products) and editing."""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.analysis.identification.types import BrandEntry, Catalogue, CategoryEntry
from app.analysis.matching.matcher import ProductAliasEntry, ProductEntry
from app.analysis.normalisation.text import normalise_text, slugify
from app.core.enums import AliasSource, AliasType, ProductLevel
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.models import Brand, BrandAlias, Category, CategoryAlias, Product, ProductAlias
from app.services import audit
from app.services.audit import Actor


def load_catalogue(session: Session) -> Catalogue:
    brands = session.scalars(
        select(Brand).where(Brand.is_active.is_(True)).options(selectinload(Brand.aliases))
    ).all()
    categories = session.scalars(select(Category).options(selectinload(Category.aliases))).all()
    return Catalogue(
        brands=[
            BrandEntry(
                id=b.id,
                slug=b.slug,
                name=b.name,
                aliases=[a.alias_normalised for a in b.aliases if not a.is_negative],
                negative_aliases=[a.alias_normalised for a in b.aliases if a.is_negative],
                base_risk=b.base_authenticity_risk,
            )
            for b in brands
        ],
        categories=[
            CategoryEntry(
                id=c.id,
                slug=c.slug,
                name=c.name,
                parent_id=c.parent_id,
                in_scope=c.in_scope,
                priority=c.priority,
                keywords=[a.alias_normalised for a in c.aliases],
            )
            for c in categories
        ],
    )


def load_products(session: Session, brand_ids: Iterable[int] | None = None) -> list[ProductEntry]:
    query = (
        select(Product).where(Product.is_active.is_(True)).options(selectinload(Product.aliases))
    )
    if brand_ids is not None:
        ids = list(brand_ids)
        if not ids:
            return []
        query = query.where(Product.brand_id.in_(ids))
    return [
        ProductEntry(
            id=p.id,
            brand_id=p.brand_id,
            category_id=p.category_id,
            level=ProductLevel(p.level),
            name=p.canonical_name,
            model_code=p.model_code,
            aliases=[
                ProductAliasEntry(text=a.alias_normalised, weight=a.weight) for a in p.aliases
            ],
        )
        for p in session.scalars(query)
    ]


# ---------------------------------------------------------------- editing


def create_brand(
    session: Session,
    *,
    name: str,
    aliases: list[str],
    negative_aliases: list[str],
    base_authenticity_risk: Decimal,
    actor: Actor,
) -> Brand:
    slug = slugify(name)
    if not slug:
        raise ValidationFailedError("brand name is empty")
    if session.scalar(select(Brand.id).where((Brand.slug == slug) | (Brand.name == name))):
        raise ConflictError(f"brand {name!r} already exists")
    brand = Brand(name=name, slug=slug, base_authenticity_risk=base_authenticity_risk)
    session.add(brand)
    session.flush()
    seen: set[str] = set()
    for alias, negative in [(a, False) for a in [name, *aliases]] + [
        (a, True) for a in negative_aliases
    ]:
        norm = normalise_text(alias)
        if norm and norm not in seen:
            seen.add(norm)
            session.add(
                BrandAlias(
                    brand_id=brand.id, alias=alias, alias_normalised=norm, is_negative=negative
                )
            )
    from app.services.seed import ensure_generic_product

    for category in session.scalars(select(Category).where(Category.in_scope.is_(True))):
        ensure_generic_product(session, brand, category)
    session.flush()
    audit.record(
        session, actor, action="brand.create", entity_type="brand", entity_id=brand.id,
        after={"name": name, "aliases": aliases, "negative_aliases": negative_aliases},
    )  # fmt: skip
    return brand


def add_brand_alias(
    session: Session, brand_id: int, alias: str, *, is_negative: bool, actor: Actor
) -> BrandAlias:
    brand = session.get(Brand, brand_id)
    if brand is None:
        raise NotFoundError(f"brand {brand_id} not found")
    norm = normalise_text(alias)
    if not norm:
        raise ValidationFailedError("alias is empty")
    row = BrandAlias(brand_id=brand_id, alias=alias, alias_normalised=norm, is_negative=is_negative)
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        raise ConflictError("that alias already exists for this brand") from exc
    audit.record(
        session, actor, action="brand.add_alias", entity_type="brand", entity_id=brand_id,
        after={"alias": alias, "negative": is_negative},
    )  # fmt: skip
    return row


def create_product(
    session: Session,
    *,
    brand_id: int,
    category_id: int,
    name: str,
    level: ProductLevel,
    model_code: str | None,
    aliases: list[str],
    actor: Actor,
) -> Product:
    if level == ProductLevel.BRAND_CATEGORY_GENERIC:
        raise ValidationFailedError("generic products are created automatically")
    if session.get(Brand, brand_id) is None:
        raise NotFoundError(f"brand {brand_id} not found")
    category = session.get(Category, category_id)
    if category is None:
        raise NotFoundError(f"category {category_id} not found")
    slug = slugify(name)
    product = Product(
        brand_id=brand_id,
        category_id=category_id,
        level=level.value,
        canonical_name=name,
        slug=slug,
        model_code=model_code,
        attributes={},
    )
    session.add(product)
    try:
        session.flush()
    except IntegrityError as exc:
        raise ConflictError("a product with that name or model code already exists") from exc
    seen: set[str] = set()
    for alias in aliases:
        norm = normalise_text(alias)
        if norm and norm not in seen:
            seen.add(norm)
            session.add(
                ProductAlias(
                    product_id=product.id,
                    alias=alias,
                    alias_normalised=norm,
                    alias_type=AliasType.NAME.value,
                    source=AliasSource.MANUAL.value,
                )
            )
    session.flush()
    audit.record(
        session, actor, action="product.create", entity_type="product", entity_id=product.id,
        after={"name": name, "brand_id": brand_id, "category_id": category_id, "aliases": aliases},
    )  # fmt: skip
    return product


def add_product_alias(
    session: Session,
    product_id: int,
    alias: str,
    *,
    weight: Decimal,
    alias_type: AliasType,
    actor: Actor,
) -> ProductAlias:
    product = session.get(Product, product_id)
    if product is None:
        raise NotFoundError(f"product {product_id} not found")
    norm = normalise_text(alias)
    if not norm:
        raise ValidationFailedError("alias is empty")
    row = ProductAlias(
        product_id=product_id,
        alias=alias,
        alias_normalised=norm,
        alias_type=alias_type.value,
        weight=weight,
        source=AliasSource.MANUAL.value,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        raise ConflictError("that alias already exists for this product") from exc
    audit.record(
        session, actor, action="product.add_alias", entity_type="product", entity_id=product_id,
        after={"alias": alias, "weight": str(weight)},
    )  # fmt: skip
    return row


def add_category_keyword(session: Session, category_id: int, keyword: str, *, actor: Actor) -> None:
    if session.get(Category, category_id) is None:
        raise NotFoundError(f"category {category_id} not found")
    norm = normalise_text(keyword)
    if not norm:
        raise ValidationFailedError("keyword is empty")
    session.add(CategoryAlias(category_id=category_id, alias=keyword, alias_normalised=norm))
    try:
        session.flush()
    except IntegrityError as exc:
        raise ConflictError("that keyword already belongs to a category") from exc
    audit.record(
        session, actor, action="category.add_keyword", entity_type="category",
        entity_id=category_id, after={"keyword": keyword},
    )  # fmt: skip
