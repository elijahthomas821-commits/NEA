from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from app.core.errors import ValidationFailedError
from app.notifications.telegram.parsing import (
    parse_amount,
    parse_amounts,
    parse_command,
    parse_comp,
    parse_listing_ref,
)

NOW = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("/start", ("start", "")),
        ("/check 12", ("check", "12")),
        ("/Price@ResaleBot 12 £40", ("price", "12 £40")),
        ("  /comp  a | b | 9 ", ("comp", "a | b | 9")),
        ("hello", None),
        ("/", None),
        ("/bad-command", None),
    ],
)
def test_parse_command(text, expected):
    assert parse_command(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("45", (Decimal("45"), None)),
        ("£45.50", (Decimal("45.50"), "GBP")),
        ("45,50", (Decimal("45.50"), None)),
        ("paid 30 eur", (Decimal("30"), "EUR")),
        ("0", None),
        ("nothing", None),
        ("", None),
        ("999999", None),
    ],
)
def test_parse_amount(text, expected):
    assert parse_amount(text) == expected


def test_parse_amounts():
    assert parse_amounts("2.95 3.49") == [Decimal("2.95"), Decimal("3.49")]
    assert parse_amounts("total £51,20") == [Decimal("51.20")]
    assert parse_amounts("no numbers") == []
    assert parse_amounts("9999999") == []  # not read as a price at all
    with pytest.raises(ValidationFailedError):
        parse_amounts("150000")


@pytest.mark.parametrize(
    ("text", "expected"), [("12", 12), ("#12", 12), (" 7 ", 7), ("abc", None), ("12a", None)]
)
def test_parse_listing_ref(text, expected):
    assert parse_listing_ref(text) == expected


class TestComp:
    def test_minimal(self):
        comp = parse_comp("Stone Island | sweatshirts | £95", now=NOW)
        assert (comp.brand, comp.category, comp.price, comp.currency) == (
            "Stone Island",
            "sweatshirts",
            Decimal("95"),
            "GBP",
        )
        assert comp.size is None
        assert comp.sold_at == NOW

    def test_full(self):
        comp = parse_comp("CP Company | jackets | 120 | M | very good | 2026-09-20", now=NOW)
        assert comp.size == "M"
        assert comp.condition == "very good"
        assert comp.sold_at == datetime(2026, 9, 20, 12, tzinfo=UTC)
        assert comp.currency is None

    def test_today_is_capped_at_now(self):
        early = datetime(2026, 9, 28, 8, 0, tzinfo=UTC)
        assert parse_comp("a | b | 1 | | | 2026-09-28", now=early).sold_at == early

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("Stone Island | sweatshirts", "Send the sale as"),
            ("Stone Island | | 95", "Send the sale as"),
            ("a | b | free", "is not a price"),
            ("a | b | 9 | L | good | 2026-13-01", "sold date"),
            ("a | b | 9 | L | good | 2026-10-01", "future"),
            ("a | b | 9 | L | good | 2026-09-01 | extra", "Too many parts"),
            ("x" * 101 + " | b | 9", "too long"),
        ],
    )
    def test_invalid(self, text, message):
        with pytest.raises(ValidationFailedError, match=message):
            parse_comp(text, now=NOW)
