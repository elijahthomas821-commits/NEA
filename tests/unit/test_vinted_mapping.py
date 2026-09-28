import pytest

from app.collectors.manual.parser import parse_submission_text
from app.collectors.vinted.mapping import (
    clean_size_label,
    find_item_url,
    map_condition_label,
    parse_item_url,
    parse_member_url,
)
from app.core.enums import Condition


class TestItemUrls:
    @pytest.mark.parametrize(
        ("url", "external_id", "slug", "site"),
        [
            (
                "https://www.vinted.co.uk/items/4829301234-stone-island-crewneck-sweatshirt",
                "4829301234",
                "stone-island-crewneck-sweatshirt",
                "vinted.co.uk",
            ),
            ("https://vinted.co.uk/items/4829301234", "4829301234", None, "vinted.co.uk"),
            (
                "https://www.vinted.fr/items/123456-sweat-stone-island?referrer=catalog",
                "123456",
                "sweat-stone-island",
                "vinted.fr",
            ),
            ("http://www.vinted.de/items/99999/", "99999", None, "vinted.de"),
            (
                "https://www.vinted.co.uk/en/items/5550001-cp-company",
                "5550001",
                "cp-company",
                "vinted.co.uk",
            ),
        ],
    )
    def test_parses_item_links(self, url, external_id, slug, site):
        ref = parse_item_url(url)
        assert ref is not None
        assert (ref.external_id, ref.slug, ref.site) == (external_id, slug, site)
        assert ref.canonical_url == f"https://www.{site}/items/{external_id}"

    @pytest.mark.parametrize(
        "url",
        [
            "https://www.vinted.co.uk/member/123-bob",
            "https://evil.example/items/123-stone-island",
            "https://vinted.co.uk.evil.example/items/123",
            "ftp://www.vinted.co.uk/items/123",
            "not a url",
            "https://www.vinted.co.uk/items/abc",
        ],
    )
    def test_rejects_other_links(self, url):
        assert parse_item_url(url) is None

    def test_slug_title_and_currency(self):
        ref = parse_item_url("https://www.vinted.co.uk/items/1234-cp-company-goggle-hoodie")
        assert ref is not None
        assert ref.slug_title == "cp company goggle hoodie"
        assert ref.default_currency == "GBP"

    def test_member_url(self):
        assert parse_member_url("https://www.vinted.co.uk/member/777-jane_d") == ("777", "jane_d")
        assert parse_member_url("https://www.vinted.co.uk/items/777") is None

    def test_find_in_shared_text(self):
        text = (
            "Check out this item on Vinted! "
            "https://www.vinted.co.uk/items/4829301234-stone-island-hoodie?share_id=abc."
        )
        found = find_item_url(text)
        assert found is not None
        assert found[1].external_id == "4829301234"


class TestLabels:
    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("New with tags", Condition.NEW_WITH_TAGS),
            ("New without tags", Condition.NEW_WITHOUT_TAGS),
            ("Very good", Condition.VERY_GOOD),
            ("Good", Condition.GOOD),
            ("Satisfactory", Condition.SATISFACTORY),
            ("Très bon état", Condition.VERY_GOOD),
            ("Neu mit Etikett", Condition.NEW_WITH_TAGS),
            ("excellent", None),
            (None, None),
        ],
    )
    def test_condition_labels(self, label, expected):
        assert map_condition_label(label) is expected

    @pytest.mark.parametrize(
        ("label", "expected"),
        [("L / 40 / 12", "L"), ("m", "M"), ("XL | 52", "XL"), ("48", "48"), (None, None)],
    )
    def test_size_labels(self, label, expected):
        assert clean_size_label(label) == expected


class TestQuickParser:
    def test_link_price_and_notes(self):
        parsed = parse_submission_text(
            "https://www.vinted.co.uk/items/4829301234-stone-island-crewneck £45 L very good"
        )
        assert parsed.external_id == "4829301234"
        assert parsed.url == "https://www.vinted.co.uk/items/4829301234"
        assert parsed.title == "stone island crewneck"
        assert str(parsed.price) == "45"
        assert parsed.currency == "GBP"
        assert parsed.notes == "L very good"

    def test_text_only(self):
        parsed = parse_submission_text("CP Company goggle hoodie navy M £60 good")
        assert parsed.external_id is None
        assert parsed.title == "CP Company goggle hoodie navy M good"
        assert str(parsed.price) == "60"

    def test_share_boilerplate_removed(self):
        parsed = parse_submission_text(
            "Check out this item on Vinted! https://www.vinted.co.uk/items/12345-moncler-maya"
        )
        assert parsed.notes == ""
        assert parsed.title == "moncler maya"

    def test_size_number_is_not_price(self):
        parsed = parse_submission_text("https://www.vinted.co.uk/items/12345-cp-jacket size 50")
        assert parsed.price is None
        assert parsed.notes == "size 50"
