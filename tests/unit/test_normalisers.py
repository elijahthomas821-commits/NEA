import pytest

from app.analysis.normalisation.colour import find_colour, normalise_colour_field
from app.analysis.normalisation.condition import (
    find_damage_terms,
    match_condition,
    match_condition_label,
)
from app.analysis.normalisation.size import (
    find_size_in_text,
    is_kids_text,
    parse_size_value,
    size_distance,
)
from app.core.enums import Condition
from tests.catalogue import sizes_config

SIZES = sizes_config()


class TestCondition:
    @pytest.mark.parametrize(
        ("text", "source", "expected"),
        [
            ("BNWT Stone Island hoodie", "title", Condition.NEW_WITH_TAGS),
            ("new without tags", "title", Condition.NEW_WITHOUT_TAGS),
            ("hoodie in very good condition", "title", Condition.VERY_GOOD),
            ("good condition, worn a few times", "title", Condition.GOOD),
            ("vgc", "title", Condition.VERY_GOOD),
            ("well worn but still nice", "description", Condition.SATISFACTORY),
            ("good", "notes", Condition.GOOD),
            ("fair", "field", Condition.SATISFACTORY),
            ("excellent", "notes", Condition.VERY_GOOD),
        ],
    )
    def test_phrases(self, text, source, expected):
        match = match_condition(text, source)
        assert match is not None
        assert match.condition is expected

    @pytest.mark.parametrize(
        "text",
        [
            "good quality cotton",  # ambiguous word in free text
            "excellent stitching",
            "no signs of wear",  # negated
            "",
            None,
        ],
    )
    def test_ignored_in_free_text(self, text):
        assert match_condition(text, "title") is None

    def test_longest_phrase_wins(self):
        assert match_condition("very good", "field").condition is Condition.VERY_GOOD
        assert match_condition("new without tags", "title").condition is Condition.NEW_WITHOUT_TAGS

    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("Very good", Condition.VERY_GOOD),
            ("very_good", Condition.VERY_GOOD),
            ("Neuf sans étiquette", Condition.NEW_WITHOUT_TAGS),
            ("brilliant", None),
        ],
    )
    def test_labels(self, label, expected):
        assert match_condition_label(label) is expected

    def test_damage_terms(self):
        assert find_damage_terms("small hole on the cuff and a stain") == ["hole", "stain"]
        assert find_damage_terms("no holes, no stains, no rips") == []
        assert find_damage_terms("zip broken") == ["zip broken"]


class TestColour:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Stone Island crewneck navy blue", "navy"),
            ("Stone Island garment dyed hoodie", None),  # "stone" is not a colour here
            ("olive green overshirt", "khaki"),
            ("charcoal grey jumper", "grey"),
            ("mint condition black jacket", "black"),
            ("camo shell", "multi"),
            (None, None),
        ],
    )
    def test_free_text(self, text, expected):
        assert find_colour(text) == expected

    def test_field_only_words(self):
        assert normalise_colour_field("Stone") == "beige"
        assert normalise_colour_field("Navy") == "navy"


class TestSize:
    @pytest.mark.parametrize(
        ("value", "brand", "expected", "system"),
        [
            ("L", None, "L", "letter"),
            ("Medium", None, "M", "letter"),
            ("X-Large", None, "XL", "letter"),
            ("2XL", None, "XXL", "letter"),
            ("IT 50", None, "L", "eu_it"),
            ("EU 48", None, "M", "eu_it"),
            ("UK 40", None, "L", "uk_chest"),
            ("40 chest", None, "L", "uk_chest"),
            ("3", "moncler", "L", "moncler"),
            ("0", "moncler", "XS", "moncler"),
            ("50", "cp-company", "L", "eu_it"),
            ("L / 40 / 12", None, "L", "letter"),
        ],
    )
    def test_values(self, value, brand, expected, system):
        result = parse_size_value(value, brand_slug=brand, config=SIZES)
        assert result.normalised == expected
        assert result.system == system

    @pytest.mark.parametrize("value", ["44", "S/M", "M-L", "chunky"])
    def test_ambiguous_values_left_unknown(self, value):
        result = parse_size_value(value, brand_slug="stone-island", config=SIZES)
        assert result.normalised is None
        assert result.ambiguous

    @pytest.mark.parametrize("value", ["Age 12", "12-13 years", "14y", "Boys L", "12 years"])
    def test_kids_sizes(self, value):
        result = parse_size_value(value, brand_slug=None, config=SIZES)
        assert result.is_kids
        assert result.normalised is None

    def test_one_size(self):
        assert parse_size_value("One size", brand_slug=None, config=SIZES).system == "one_size"

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Stone Island Crewneck Navy L", "L"),
            ("Stone Island hoodie size M navy", "M"),
            ("CP Company jacket IT 52", "XL"),
            ("Ralph Lauren jacket 42 chest", "XL"),
            ("Moncler Maya size 3", "L"),
            ("large logo hoodie", None),  # "large" alone is not a size in a title
            ("men's hoodie", None),
            ("hoodie in medium weight fleece", None),
        ],
    )
    def test_find_in_title(self, text, expected):
        brand = "moncler" if "Moncler" in text else None
        result = find_size_in_text(text, brand_slug=brand, config=SIZES, source="title")
        assert result.normalised == expected

    def test_notes_accept_lowercase_letters(self):
        result = find_size_in_text(
            "l very good", brand_slug=None, config=SIZES, source="notes",
            case_insensitive_letters=True,
        )  # fmt: skip
        assert result.normalised == "L"

    def test_worn_for_years_is_not_kids(self):
        assert not is_kids_text("worn for 2 years, great condition")
        assert is_kids_text("boys hoodie age 12")

    def test_distance(self):
        assert size_distance("M", "XL") == 2
        assert size_distance("M", None) is None
