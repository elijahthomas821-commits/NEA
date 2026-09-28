"""Brands, categories, products and an identification preview."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.analysis.identification.rules import identify
from app.analysis.identification.types import ListingText
from app.analysis.matching.matcher import match_product
from app.api.deps import PrincipalDep, SessionDep
from app.core.errors import NotFoundError
from app.models import Brand, Category, Product
from app.schemas.catalogue import (
    AliasIn,
    BrandIn,
    BrandOut,
    CategoryOut,
    IdentifyIn,
    KeywordIn,
    ProductAliasIn,
    ProductIn,
    ProductOut,
)
from app.services import catalogue as catalogue_service
from app.services.config_service import ConfigService

router = APIRouter(tags=["catalogue"])


def _brand_out(brand: Brand) -> BrandOut:
    return BrandOut(
        id=brand.id,
        name=brand.name,
        slug=brand.slug,
        base_authenticity_risk=brand.base_authenticity_risk,
        is_active=brand.is_active,
        aliases=sorted(a.alias_normalised for a in brand.aliases if not a.is_negative),
        negative_aliases=sorted(a.alias_normalised for a in brand.aliases if a.is_negative),
    )


def _product_out(product: Product) -> ProductOut:
    return ProductOut(
        id=product.id,
        brand_id=product.brand_id,
        category_id=product.category_id,
        level=product.level,
        name=product.canonical_name,
        model_code=product.model_code,
        aliases=sorted(a.alias_normalised for a in product.aliases),
    )


@router.get("/brands", response_model=list[BrandOut])
def list_brands(principal: PrincipalDep, session: SessionDep) -> list[BrandOut]:
    brands = session.scalars(
        select(Brand).options(selectinload(Brand.aliases)).order_by(Brand.name)
    ).all()
    return [_brand_out(b) for b in brands]


@router.post("/brands", response_model=BrandOut, status_code=201)
def create_brand(body: BrandIn, principal: PrincipalDep, session: SessionDep) -> BrandOut:
    brand = catalogue_service.create_brand(
        session,
        name=body.name,
        aliases=body.aliases,
        negative_aliases=body.negative_aliases,
        base_authenticity_risk=body.base_authenticity_risk,
        actor=principal.actor,
    )
    session.commit()
    session.refresh(brand)
    return _brand_out(brand)


@router.post("/brands/{brand_id}/aliases", response_model=BrandOut, status_code=201)
def add_brand_alias(
    brand_id: int, body: AliasIn, principal: PrincipalDep, session: SessionDep
) -> BrandOut:
    catalogue_service.add_brand_alias(
        session, brand_id, body.alias, is_negative=body.is_negative, actor=principal.actor
    )
    session.commit()
    brand = session.get(Brand, brand_id)
    assert brand is not None
    session.refresh(brand)
    return _brand_out(brand)


@router.get("/categories", response_model=list[CategoryOut])
def list_categories(principal: PrincipalDep, session: SessionDep) -> list[CategoryOut]:
    categories = session.scalars(
        select(Category).options(selectinload(Category.aliases)).order_by(Category.id)
    ).all()
    return [
        CategoryOut(
            id=c.id,
            slug=c.slug,
            name=c.name,
            parent_id=c.parent_id,
            in_scope=c.in_scope,
            keywords=sorted(a.alias_normalised for a in c.aliases),
        )
        for c in categories
    ]


@router.post("/categories/{category_id}/keywords", status_code=201)
def add_category_keyword(
    category_id: int, body: KeywordIn, principal: PrincipalDep, session: SessionDep
) -> dict[str, str]:
    catalogue_service.add_category_keyword(
        session, category_id, body.keyword, actor=principal.actor
    )
    session.commit()
    return {"status": "created"}


@router.get("/products", response_model=list[ProductOut])
def list_products(
    principal: PrincipalDep,
    session: SessionDep,
    brand_id: int | None = None,
    category_id: int | None = None,
) -> list[ProductOut]:
    query = select(Product).options(selectinload(Product.aliases)).order_by(Product.id)
    if brand_id is not None:
        query = query.where(Product.brand_id == brand_id)
    if category_id is not None:
        query = query.where(Product.category_id == category_id)
    return [_product_out(p) for p in session.scalars(query)]


@router.post("/products", response_model=ProductOut, status_code=201)
def create_product(body: ProductIn, principal: PrincipalDep, session: SessionDep) -> ProductOut:
    product = catalogue_service.create_product(
        session,
        brand_id=body.brand_id,
        category_id=body.category_id,
        name=body.name,
        level=body.level,
        model_code=body.model_code,
        aliases=body.aliases,
        actor=principal.actor,
    )
    session.commit()
    session.refresh(product)
    return _product_out(product)


@router.post("/products/{product_id}/aliases", response_model=ProductOut, status_code=201)
def add_product_alias(
    product_id: int, body: ProductAliasIn, principal: PrincipalDep, session: SessionDep
) -> ProductOut:
    catalogue_service.add_product_alias(
        session,
        product_id,
        body.alias,
        weight=body.weight,
        alias_type=body.alias_type,
        actor=principal.actor,
    )
    session.commit()
    product = session.get(Product, product_id)
    if product is None:  # pragma: no cover - just created an alias for it
        raise NotFoundError("product vanished")
    session.refresh(product)
    return _product_out(product)


@router.post("/identify")
def identify_preview(
    body: IdentifyIn, principal: PrincipalDep, session: SessionDep
) -> dict[str, Any]:
    """Rules-only identification of the given text, with product match. Stores nothing."""
    bundle = ConfigService(session).bundle()
    catalogue = catalogue_service.load_catalogue(session)
    ident = identify(
        ListingText(
            title=body.title,
            description=body.description,
            raw_brand=body.brand,
            raw_category=body.category,
            raw_size=body.size,
            raw_colour=body.colour,
            raw_condition=body.condition,
            operator_notes=body.notes,
        ),
        catalogue,
        bundle.identification,
        bundle.sizes,
    )
    brand_ids = [ident.brand_id] if ident.brand_id is not None else []
    match = match_product(
        ident,
        catalogue_service.load_products(session, brand_ids),
        bundle.identification.matching,
    )
    return {
        "identification": ident.model_dump(mode="json", exclude={"tokens"}),
        "confidence": str(ident.confidence),
        "match": match.model_dump(mode="json"),
    }
