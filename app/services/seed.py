"""Idempotent seeding of reference data and default configuration from the YAML defaults.

Seeding only *adds* what is missing. It never overwrites rows you have edited (brands,
aliases, products) and never replaces an active configuration unless ``update_config`` is set,
in which case a new configuration version is created (the old one stays for reproducibility).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.normalisation.text import normalise_text, unique_normalised
from app.config.loader import load_catalogue_file, load_default_payload
from app.core.enums import AliasSource, AliasType, ConfigKind, ProductLevel
from app.models import (
    Brand,
    BrandAlias,
    Category,
    CategoryAlias,
    ConfigVersion,
    Marketplace,
    Product,
    ProductAlias,
)
from app.services.audit import Actor
from app.services.config_service import ConfigService

MARKETPLACES = [
    ("vinted", "Vinted", "https://www.vinted.co.uk"),
    ("ebay", "eBay", "https://www.ebay.co.uk"),
    ("depop", "Depop", "https://www.depop.com"),
    ("other", "Other", None),
]


@dataclass
class SeedReport:
    created: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def bump(self, key: str, n: int = 1) -> None:
        self.created[key] = self.created.get(key, 0) + n


def seed_reference_data(
    session: Session, *, update_config: bool = False, actor: Actor | None = None
) -> SeedReport:
    actor = actor or Actor.system("seed")
    report = SeedReport()
    _seed_marketplaces(session, report)
    _seed_categories(session, report)
    _seed_brands(session, report)
    _seed_products(session, report)
    _seed_generic_products(session, report)
    _seed_config(session, report, update_config=update_config, actor=actor)
    session.flush()
    return report


def _seed_marketplaces(session: Session, report: SeedReport) -> None:
    existing = set(session.scalars(select(Marketplace.code)))
    for code, name, url in MARKETPLACES:
        if code not in existing:
            session.add(Marketplace(code=code, name=name, base_url=url, enabled=True))
            report.bump("marketplaces")
    session.flush()


def _seed_categories(session: Session, report: SeedReport) -> None:
    data = load_catalogue_file("categories")
    by_slug = {c.slug: c for c in session.scalars(select(Category))}
    taken = {a.alias_normalised: a.category_id for a in session.scalars(select(CategoryAlias))}

    def visit(node: dict[str, Any], parent: Category | None, depth: int) -> None:
        slug = node["slug"]
        category = by_slug.get(slug)
        if category is None:
            category = Category(
                slug=slug,
                name=node["name"],
                parent_id=parent.id if parent else None,
                level=depth,
                in_scope=bool(node.get("in_scope", False)),
                priority=int(node.get("priority", 0)),
            )
            session.add(category)
            session.flush()
            by_slug[slug] = category
            report.bump("categories")
        for alias_norm in unique_normalised(node.get("keywords", [])):
            owner = taken.get(alias_norm)
            if owner is None:
                session.add(
                    CategoryAlias(
                        category_id=category.id, alias=alias_norm, alias_normalised=alias_norm
                    )
                )
                taken[alias_norm] = category.id
                report.bump("category_aliases")
            elif owner != category.id:
                report.warnings.append(
                    f"category keyword {alias_norm!r} already belongs to another category"
                )
        for child in node.get("children", []):
            visit(child, category, depth + 1)

    for root in data.get("categories", []):
        visit(root, None, 0)
    session.flush()


def _seed_brands(session: Session, report: SeedReport) -> None:
    data = load_catalogue_file("brands")
    by_slug = {b.slug: b for b in session.scalars(select(Brand))}
    for entry in data.get("brands", []):
        brand = by_slug.get(entry["slug"])
        if brand is None:
            brand = Brand(
                name=entry["name"],
                slug=entry["slug"],
                base_authenticity_risk=Decimal(str(entry.get("base_authenticity_risk", "0.3"))),
            )
            session.add(brand)
            session.flush()
            by_slug[brand.slug] = brand
            report.bump("brands")
        existing = {
            a.alias_normalised
            for a in session.scalars(select(BrandAlias).where(BrandAlias.brand_id == brand.id))
        }
        # The brand name itself is always an alias.
        positives = unique_normalised([entry["name"], *entry.get("aliases", [])])
        negatives = unique_normalised(entry.get("negative_aliases", []))
        for alias_norm, is_negative in [(a, False) for a in positives] + [
            (a, True) for a in negatives
        ]:
            if alias_norm in existing:
                continue
            session.add(
                BrandAlias(
                    brand_id=brand.id,
                    alias=alias_norm,
                    alias_normalised=alias_norm,
                    is_negative=is_negative,
                )
            )
            existing.add(alias_norm)
            report.bump("brand_aliases")
    session.flush()


def _seed_products(session: Session, report: SeedReport) -> None:
    data = load_catalogue_file("products")
    brands = {b.slug: b for b in session.scalars(select(Brand))}
    categories = {c.slug: c for c in session.scalars(select(Category))}
    for entry in data.get("products", []):
        brand = brands.get(entry["brand"])
        category = categories.get(entry["category"])
        if brand is None or category is None:
            report.warnings.append(f"product {entry.get('slug')!r}: unknown brand or category")
            continue
        product = session.scalar(
            select(Product).where(Product.brand_id == brand.id, Product.slug == entry["slug"])
        )
        if product is None:
            product = Product(
                brand_id=brand.id,
                category_id=category.id,
                level=ProductLevel(entry.get("level", "product_line")).value,
                canonical_name=entry["name"],
                slug=entry["slug"],
                model_code=entry.get("model_code"),
                attributes={},
            )
            session.add(product)
            session.flush()
            report.bump("products")
        existing = {
            a.alias_normalised
            for a in session.scalars(
                select(ProductAlias).where(ProductAlias.product_id == product.id)
            )
        }
        for raw in entry.get("aliases", []):
            alias_text = raw["alias"] if isinstance(raw, dict) else str(raw)
            weight = Decimal(str(raw.get("weight", "1.0"))) if isinstance(raw, dict) else Decimal(1)
            alias_type = raw.get("type", "name") if isinstance(raw, dict) else "name"
            norm = normalise_text(alias_text)
            if not norm or norm in existing:
                continue
            session.add(
                ProductAlias(
                    product_id=product.id,
                    alias=alias_text,
                    alias_normalised=norm,
                    alias_type=AliasType(alias_type).value,
                    weight=weight,
                    source=AliasSource.SEED.value,
                )
            )
            existing.add(norm)
            report.bump("product_aliases")
    session.flush()


def ensure_generic_product(session: Session, brand: Brand, category: Category) -> Product:
    product = session.scalar(
        select(Product).where(
            Product.brand_id == brand.id,
            Product.category_id == category.id,
            Product.level == ProductLevel.BRAND_CATEGORY_GENERIC.value,
        )
    )
    if product is None:
        product = Product(
            brand_id=brand.id,
            category_id=category.id,
            level=ProductLevel.BRAND_CATEGORY_GENERIC.value,
            canonical_name=f"{brand.name} {category.name.lower()} (any model)",
            slug=f"{category.slug}-generic",
            attributes={},
        )
        session.add(product)
        session.flush()
    return product


def _seed_generic_products(session: Session, report: SeedReport) -> None:
    brands = list(session.scalars(select(Brand).where(Brand.is_active.is_(True))))
    categories = list(session.scalars(select(Category).where(Category.in_scope.is_(True))))
    existing = {
        (p.brand_id, p.category_id)
        for p in session.scalars(
            select(Product).where(Product.level == ProductLevel.BRAND_CATEGORY_GENERIC.value)
        )
    }
    for brand in brands:
        for category in categories:
            if (brand.id, category.id) not in existing:
                ensure_generic_product(session, brand, category)
                report.bump("generic_products")


def _seed_config(
    session: Session, report: SeedReport, *, update_config: bool, actor: Actor
) -> None:
    service = ConfigService(session)
    for kind in ConfigKind:
        has_active = session.scalar(
            select(ConfigVersion.id).where(
                ConfigVersion.kind == kind.value, ConfigVersion.is_active.is_(True)
            )
        )
        if has_active is not None and not update_config:
            continue
        payload = load_default_payload(kind)
        _, created = service.create_version(
            kind, payload, actor=actor, note="seeded from app/config/defaults"
        )
        if created:
            report.bump("config_versions")
