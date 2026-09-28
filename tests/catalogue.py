"""Build the analysis-layer catalogue from the seed YAML without a database."""

from __future__ import annotations

from decimal import Decimal
from functools import lru_cache

from app.analysis.identification.types import BrandEntry, Catalogue, CategoryEntry
from app.analysis.matching.matcher import ProductAliasEntry, ProductEntry
from app.analysis.normalisation.text import normalise_text, unique_normalised
from app.config.loader import load_catalogue_file, load_default_config
from app.config.schemas import IdentificationConfig, SizesConfig
from app.core.enums import ConfigKind, ProductLevel


@lru_cache(maxsize=1)
def catalogue() -> Catalogue:
    brands = []
    for i, entry in enumerate(load_catalogue_file("brands")["brands"], start=1):
        brands.append(
            BrandEntry(
                id=i,
                slug=entry["slug"],
                name=entry["name"],
                aliases=unique_normalised([entry["name"], *entry.get("aliases", [])]),
                negative_aliases=unique_normalised(entry.get("negative_aliases", [])),
                base_risk=Decimal(str(entry.get("base_authenticity_risk", "0.3"))),
            )
        )
    categories: list[CategoryEntry] = []
    counter = iter(range(100, 1000))

    def visit(node, parent_id):
        cat_id = next(counter)
        categories.append(
            CategoryEntry(
                id=cat_id,
                slug=node["slug"],
                name=node["name"],
                parent_id=parent_id,
                in_scope=bool(node.get("in_scope", False)),
                priority=int(node.get("priority", 0)),
                keywords=unique_normalised(node.get("keywords", [])),
            )
        )
        for child in node.get("children", []):
            visit(child, cat_id)

    for root in load_catalogue_file("categories")["categories"]:
        visit(root, None)
    return Catalogue(brands=brands, categories=categories)


@lru_cache(maxsize=1)
def products() -> tuple[ProductEntry, ...]:
    cat = catalogue()
    out: list[ProductEntry] = []
    next_id = iter(range(1000, 100000))
    for entry in load_catalogue_file("products")["products"]:
        brand = cat.brand_by_slug(entry["brand"])
        category = cat.category_by_slug(entry["category"])
        aliases = [
            ProductAliasEntry(
                text=normalise_text(a["alias"] if isinstance(a, dict) else a),
                weight=Decimal(str(a.get("weight", "1.0"))) if isinstance(a, dict) else Decimal(1),
            )
            for a in entry.get("aliases", [])
        ]
        out.append(
            ProductEntry(
                id=next(next_id),
                brand_id=brand.id,
                category_id=category.id,
                level=ProductLevel(entry.get("level", "product_line")),
                name=entry["name"],
                model_code=entry.get("model_code"),
                aliases=aliases,
            )
        )
    for brand in cat.brands:
        for category in cat.categories:
            if category.in_scope:
                out.append(
                    ProductEntry(
                        id=next(next_id),
                        brand_id=brand.id,
                        category_id=category.id,
                        level=ProductLevel.BRAND_CATEGORY_GENERIC,
                        name=f"{brand.name} {category.name} (any model)",
                    )
                )
    return tuple(out)


def identification_config() -> IdentificationConfig:
    return load_default_config(ConfigKind.IDENTIFICATION)  # type: ignore[return-value]


def sizes_config() -> SizesConfig:
    return load_default_config(ConfigKind.SIZES)  # type: ignore[return-value]
