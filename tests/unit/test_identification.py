from decimal import Decimal

import pytest

from app.analysis.identification.ai_merge import (
    AIIdentityEvidence,
    apply_mislabel,
    is_mislabel_candidate,
    merge_ai,
)
from app.analysis.identification.rules import identify
from app.analysis.identification.types import ListingText
from app.analysis.matching.matcher import match_product
from app.core.enums import Condition, IdentificationMethod
from tests.catalogue import catalogue, identification_config, products, sizes_config

CAT = catalogue()
ID_CFG = identification_config()
SIZES = sizes_config()


def run(**fields) -> object:
    return identify(ListingText(**fields), CAT, ID_CFG, SIZES)


def codes(result) -> set[str]:
    return {c.code for c in result.contradictions}


class TestBrand:
    def test_field_and_title_agree(self):
        r = run(title="Stone Island crewneck sweatshirt navy L", raw_brand="Stone Island")
        assert r.brand_slug == "stone-island"
        assert r.brand_confidence > Decimal("0.95")
        assert r.brand_source == "field"
        assert not r.contradictions

    def test_title_only(self):
        r = run(title="C.P. Company goggle hoodie")
        assert r.brand_slug == "cp-company"
        assert r.brand_confidence == Decimal("0.900")

    def test_misspelled_brand_is_fuzzy_matched(self):
        r = run(title="Vintage Stone Islnad crewneck")
        assert r.brand_slug == "stone-island"
        assert r.brand_source == "fuzzy"
        assert r.brand_confidence < Decimal("0.9")

    def test_unknown_brand(self):
        r = run(title="Nike Tech Fleece hoodie", raw_brand="Nike")
        assert r.brand_id is None
        assert r.unknown_brand == "Nike"

    def test_contradictory_field_and_title(self):
        r = run(title="Stone Island overshirt", raw_brand="C.P. Company")
        assert r.brand_slug == "cp-company"  # the seller's structured choice
        assert "BRAND_FIELD_TITLE_MISMATCH" in codes(r)
        assert r.brand_confidence < Decimal("0.6")

    def test_unknown_field_brand_but_catalogue_brand_in_title(self):
        r = run(title="Stone Island hoodie", raw_brand="Nike")
        assert r.brand_slug == "stone-island"
        assert "BRAND_FIELD_TITLE_MISMATCH" in codes(r)

    def test_multiple_brands(self):
        r = run(title="Stone Island not CP Company hoodie")
        # "not CP Company" is negated, so only Stone Island counts.
        assert r.brand_slug == "stone-island"
        assert "MULTIPLE_BRANDS" not in codes(r)
        r2 = run(title="Stone Island Moncler bundle")
        assert "MULTIPLE_BRANDS" in codes(r2)

    def test_generic_brand_field(self):
        r = run(title="Navy overshirt with sleeve badge", raw_brand="Unbranded")
        assert r.brand_id is None
        assert r.brand_field_generic

    def test_generic_field_but_brand_in_title(self):
        r = run(title="Moncler Maya jacket", raw_brand="Other")
        assert r.brand_slug == "moncler"
        assert r.brand_confidence < Decimal("0.9")

    def test_look_alike_wording(self):
        r = run(title="Stone Island style overshirt with badge")
        assert r.brand_id is None
        assert any("look-alike" in t for t in r.replica_terms)

    def test_replica_language_lowers_confidence(self):
        r = run(title="Stone Island crewneck 1:1 replica", raw_brand="Stone Island")
        assert r.brand_slug == "stone-island"
        assert {"replica", "1 1"} <= set(r.replica_terms)
        assert r.brand_confidence < Decimal("0.25")

    def test_negated_replica_language_is_ignored(self):
        r = run(
            title="Stone Island crewneck",
            raw_brand="Stone Island",
            description="100% genuine, not fake, no replicas here",
        )
        assert r.replica_terms == []

    def test_operator_notes_win(self):
        r = run(title="Navy jacket", raw_brand="Other", operator_notes="moncler size 3 good")
        assert r.brand_slug == "moncler"
        assert r.brand_source == "notes"
        assert r.size.normalised == "L"
        assert r.condition is Condition.GOOD


class TestCategoryAndAttributes:
    @pytest.mark.parametrize(
        ("title", "raw_category", "expected"),
        [
            ("Stone Island crewneck sweatshirt", None, "sweatshirts"),
            ("CP Company goggle hoodie", None, "hoodies"),
            ("Stone Island hooded sweatshirt", None, "hoodies"),
            ("Moncler Maya down jacket", None, "jackets"),
            ("Stone Island nylon metal overshirt", None, "jackets"),
            ("Stone Island knitted jumper", None, "knitwear"),
            ("Ralph Lauren polo shirt", None, "t-shirts"),
            ("CP Company goggle hoodie", "Hoodies & sweatshirts", "hoodies"),
            ("Burberry hooded jacket", None, "jackets"),
        ],
    )
    def test_categories(self, title, raw_category, expected):
        r = run(title=title, raw_category=raw_category)
        assert r.category_slug == expected

    def test_out_of_scope_flag(self):
        assert run(title="Stone Island cap").category_in_scope is False
        assert run(title="Stone Island hoodie").category_in_scope is True

    def test_category_contradiction(self):
        r = run(title="Stone Island hoodie", raw_category="Jackets")
        assert r.category_slug == "jackets"
        assert "CATEGORY_MISMATCH" in codes(r)

    def test_size_contradiction(self):
        r = run(title="Stone Island hoodie size M", raw_size="XL")
        assert r.size.normalised == "XL"
        assert "SIZE_MISMATCH" in codes(r)

    def test_kids_size_from_title(self):
        r = run(title="Stone Island junior hoodie", raw_size="L")
        assert r.size.is_kids

    def test_condition_and_colour_and_damage(self):
        r = run(
            title="Stone Island crewneck black",
            raw_condition="Good",
            description="small hole on the cuff",
        )
        assert r.condition is Condition.GOOD
        assert r.condition_source == "field"
        assert r.colour == "black"
        assert r.damage_terms == ["hole"]

    def test_model_tokens_exclude_brand_size_colour(self):
        r = run(title="Stone Island Crinkle Reps jacket navy L", raw_brand="Stone Island")
        assert "crinkle" in r.model_tokens
        assert not {"stone", "island", "navy", "jacket"} & set(r.model_tokens)


class TestMatching:
    def _match(self, **fields):
        ident = run(**fields)
        return ident, match_product(ident, list(products()), ID_CFG.matching)

    def test_specific_model(self):
        _, m = self._match(title="Stone Island Crinkle Reps jacket", raw_brand="Stone Island")
        assert m.method == "alias"
        assert "Crinkle Reps" in m.candidates[0].name
        assert m.confidence > Decimal("0.75")

    def test_category_disambiguates_shared_alias(self):
        _, hoodie = self._match(title="CP Company goggle hoodie")
        _, jacket = self._match(title="CP Company goggle jacket")
        names = {c.product_id: c.name for c in [*hoodie.candidates, *jacket.candidates]}
        assert "hoodie" in names[hoodie.product_id].lower()
        assert "jacket" in names[jacket.product_id].lower()

    def test_generic_fallback(self):
        ident, m = self._match(title="Stone Island hoodie navy", raw_brand="Stone Island")
        assert m.method == "generic"
        assert m.product_id is not None
        assert m.confidence == (ident.brand_confidence * ident.category_confidence).quantize(
            Decimal("0.001")
        )

    def test_clear_listings_pass_default_confidence_gate(self):
        # Link-only submissions (title from the URL slug) must be able to qualify.
        for title in ("stone island crinkle reps jacket", "cp company goggle hoodie"):
            _, m = self._match(title=title)
            assert m.confidence >= Decimal("0.75"), title

    def test_unknown_brand_matches_nothing(self):
        _, m = self._match(title="Nike hoodie", raw_brand="Nike")
        assert m.product_id is None
        assert m.method == "none"

    def test_out_of_scope_category_has_no_generic(self):
        _, m = self._match(title="Stone Island cap")
        assert m.product_id is None

    def test_misspelled_model_fuzzy(self):
        _, m = self._match(title="Stone Island crinkle repps jacket", raw_brand="Stone Island")
        assert m.product_id is not None
        assert m.method in {"fuzzy", "generic"}


class TestAIMerge:
    def test_ai_fills_unknown_brand_with_cap(self):
        ident = run(title="Navy overshirt", raw_brand="Other")
        merged = merge_ai(
            ident,
            AIIdentityEvidence(brand_slug="stone-island", confidence=Decimal("0.99")),
            CAT,
            ID_CFG.ai,
        )
        assert merged.brand_slug == "stone-island"
        assert merged.brand_confidence == Decimal("0.800")  # capped
        assert merged.method is IdentificationMethod.AI

    def test_agreement_boosts(self):
        ident = run(title="CP Company hoodie")
        merged = merge_ai(
            ident, AIIdentityEvidence(brand_slug="cp-company", confidence=Decimal("0.8")),
            CAT, ID_CFG.ai,
        )  # fmt: skip
        assert merged.brand_confidence > ident.brand_confidence
        assert merged.method is IdentificationMethod.RULES_AI

    def test_disagreement_is_a_contradiction(self):
        ident = run(title="CP Company hoodie")
        merged = merge_ai(
            ident, AIIdentityEvidence(brand_slug="stone-island", confidence=Decimal("0.8")),
            CAT, ID_CFG.ai,
        )  # fmt: skip
        assert merged.brand_slug == "cp-company"
        assert "AI_BRAND_DISAGREES" in codes(merged)
        assert merged.brand_confidence < ident.brand_confidence

    def test_ai_unknown_changes_nothing(self):
        ident = run(title="CP Company hoodie")
        merged = merge_ai(ident, AIIdentityEvidence(), CAT, ID_CFG.ai)
        assert merged.brand_confidence == ident.brand_confidence


class TestMislabel:
    def test_candidate_and_application(self):
        ident = run(title="Navy overshirt with arm badge", raw_brand="Unbranded")
        ok, reasons = is_mislabel_candidate(
            ident, price=Decimal("25"), image_count=3, rules=ID_CFG.mislabel
        )
        assert ok, reasons
        adopted = apply_mislabel(
            ident,
            AIIdentityEvidence(
                photo_brand_slug="stone-island",
                photo_brand_confidence=Decimal("0.9"),
                photo_brand_evidence=["compass badge visible on left sleeve"],
            ),
            CAT,
            ID_CFG.mislabel,
        )
        assert adopted.brand_slug == "stone-island"
        assert adopted.mislabel
        assert adopted.brand_confidence == Decimal("0.600")  # capped
        assert adopted.method is IdentificationMethod.MISLABEL_AI

    @pytest.mark.parametrize(
        ("fields", "price", "images", "reason"),
        [
            ({"title": "Stone Island overshirt"}, "25", 3, "brand already identified"),
            ({"title": "Navy overshirt badge", "raw_brand": "Other"}, "500", 3, "price"),
            ({"title": "Navy overshirt badge", "raw_brand": "Other"}, "25", 0, "no photos"),
            ({"title": "Navy jacket", "raw_brand": "Other"}, "25", 3, "keywords"),
            ({"title": "Navy cap with badge", "raw_brand": "Other"}, "25", 3, "scope"),
        ],
    )
    def test_not_candidates(self, fields, price, images, reason):
        ok, reasons = is_mislabel_candidate(
            run(**fields), price=Decimal(price), image_count=images, rules=ID_CFG.mislabel
        )
        assert not ok
        assert reason in " ".join(reasons)

    def test_low_confidence_photo_evidence_ignored(self):
        ident = run(title="Navy overshirt with badge", raw_brand="Other")
        adopted = apply_mislabel(
            ident,
            AIIdentityEvidence(
                photo_brand_slug="stone-island", photo_brand_confidence=Decimal("0.3")
            ),
            CAT,
            ID_CFG.mislabel,
        )
        assert adopted.brand_id is None
