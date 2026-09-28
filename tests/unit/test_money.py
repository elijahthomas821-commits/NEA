from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.core.money import (
    format_money,
    format_money_short,
    format_percent,
    normalise_currency,
    parse_price,
    round_down_money,
    round_money,
    to_decimal,
)


class TestToDecimal:
    def test_rejects_float(self):
        with pytest.raises(TypeError):
            to_decimal(0.1)  # type: ignore[arg-type]

    def test_rejects_bool(self):
        with pytest.raises(TypeError):
            to_decimal(True)  # type: ignore[arg-type]

    def test_accepts_str_int_decimal(self):
        assert to_decimal("45.50") == Decimal("45.50")
        assert to_decimal(3) == Decimal(3)
        assert to_decimal(Decimal("1.1")) == Decimal("1.1")

    @pytest.mark.parametrize("bad", ["abc", "1,5", "NaN", "Infinity"])
    def test_rejects_non_numeric_or_non_finite(self, bad):
        with pytest.raises(ValueError, match=r"decimal|finite"):
            to_decimal(bad)


class TestRounding:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [("1.005", "1.01"), ("1.004", "1.00"), ("2.675", "2.68"), ("-1.005", "-1.01")],
    )
    def test_round_half_up(self, value, expected):
        assert round_money(Decimal(value)) == Decimal(expected)

    @pytest.mark.parametrize(
        ("value", "expected"), [("62.999", "62.99"), ("62.991", "62.99"), ("62.00", "62.00")]
    )
    def test_round_down(self, value, expected):
        assert round_down_money(Decimal(value)) == Decimal(expected)

    @given(st.decimals(min_value=0, max_value=10**6, allow_nan=False, places=6))
    def test_round_down_never_exceeds_value(self, value):
        assert round_down_money(value) <= value
        assert value - round_down_money(value) < Decimal("0.01")


class TestFormatting:
    def test_format_gbp(self):
        assert format_money(Decimal("1234.5"), "GBP") == "£1,234.50"

    def test_format_negative(self):
        assert format_money(Decimal("-3.2"), "GBP") == "-£3.20"

    def test_format_unknown_currency(self):
        assert format_money(Decimal("10"), "CHF") == "10.00 CHF"

    def test_short(self):
        assert format_money_short(Decimal("110.00"), "GBP") == "£110"
        assert format_money_short(Decimal("110.40"), "GBP") == "£110.40"

    def test_percent(self):
        assert format_percent(Decimal("0.764")) == "76%"
        assert format_percent(Decimal("0.7649"), 1) == "76.5%"

    def test_normalise_currency(self):
        assert normalise_currency(" gbp ") == "GBP"
        assert normalise_currency("£") == "GBP"
        with pytest.raises(ValueError, match="invalid currency"):
            normalise_currency("pounds")


class TestParsePrice:
    @pytest.mark.parametrize(
        ("text", "amount", "currency"),
        [
            ("Stone Island hoodie £45 L", "45", "GBP"),
            ("price £45.50 ono", "45.50", "GBP"),
            ("45.50£", "45.50", "GBP"),
            ("€40", "40", "EUR"),
            ("45,50 €", "45.50", "EUR"),
            ("£1,250", "1250", "GBP"),
            ("60 gbp", "60", "GBP"),
            ("$99.99", "99.99", "USD"),
        ],
    )
    def test_finds_marked_prices(self, text, amount, currency):
        assert parse_price(text) == (Decimal(amount), currency)

    @pytest.mark.parametrize("text", ["size 48", "UK 40 chest", "moncler 3", "no price here"])
    def test_ignores_unmarked_numbers(self, text):
        assert parse_price(text) is None

    def test_unmarked_allowed_when_requested(self):
        assert parse_price("45", require_marker=False) == (Decimal("45"), None)

    def test_zero_is_not_a_price(self):
        assert parse_price("£0") is None
