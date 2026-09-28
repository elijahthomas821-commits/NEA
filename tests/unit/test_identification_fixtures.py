"""Regression suite: realistic listings across all brands and categories."""

from pathlib import Path

import pytest
import yaml

from app.analysis.identification.rules import identify
from app.analysis.identification.types import ListingText
from app.analysis.matching.matcher import match_product
from tests.catalogue import catalogue, identification_config, products, sizes_config

FIXTURES = yaml.safe_load((Path(__file__).parents[1] / "fixtures" / "listings.yaml").read_text())
CASES = FIXTURES["listings"]


@pytest.mark.parametrize("case", CASES, ids=[c["title"][:40] for c in CASES])
def test_listing_fixture(case):
    cfg = identification_config()
    ident = identify(
        ListingText(
            title=case["title"],
            raw_brand=case.get("brand_field"),
            raw_category=case.get("category_field"),
            raw_size=case.get("size"),
            raw_condition=case.get("condition"),
        ),
        catalogue(),
        cfg,
        sizes_config(),
    )
    expect = case["expect"]
    assert ident.brand_slug == expect["brand"]
    assert ident.category_slug == expect["category"]
    if "size" in expect:
        assert ident.size.normalised == expect["size"]
    if "condition" in expect:
        assert ident.condition == expect["condition"]
    if "colour" in expect:
        assert ident.colour == expect["colour"]
    if expect.get("kids"):
        assert ident.size.is_kids
    if "product" in expect:
        match = match_product(ident, list(products()), cfg.matching)
        names = {p.id: p.name for p in products()}
        if expect["product"] is None:
            assert match.product_id is None
        else:
            assert match.product_id is not None, match
            assert expect["product"].lower() in names[match.product_id].lower()


def test_fixture_coverage():
    brands = {c["expect"]["brand"] for c in CASES}
    categories = {(c["expect"]["brand"], c["expect"]["category"]) for c in CASES}
    assert {"stone-island", "cp-company", "ralph-lauren", "moncler", "burberry"} <= brands
    for brand in ("stone-island", "cp-company", "ralph-lauren", "moncler", "burberry"):
        for category in ("sweatshirts", "hoodies", "jackets"):
            assert (brand, category) in categories, (brand, category)
