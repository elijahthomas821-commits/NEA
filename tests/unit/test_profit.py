"""Fees, profit, ROI and maximum purchase price.

The worked examples here are the ones in docs/financial-calculations.md; they must stay exact
to the penny.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from app.analysis.profit.fees import compute_fee, variable_fee
from app.analysis.profit.max_price import max_purchase_price, search_price
from app.analysis.profit.model import Extras, profit_breakdown
from app.config.loader import load_default_config
from app.config.schemas import FeeRule, FeesConfig
from app.core.enums import ConfigKind

D = Decimal
FEES: FeesConfig = load_default_config(ConfigKind.FEES)  # type: ignore[assignment]
NO_EXTRAS = Extras()
money = st.decimals(
    min_value="0.01", max_value=2000, places=2, allow_nan=False, allow_infinity=False
)


class TestFees:
    def test_vinted_buyer_protection(self):
        rule = FEES.purchase_channels["vinted"].buyer_fee
        assert compute_fee(rule, D("45.00")) == D("2.95")  # 0.70 + 2.25
        assert compute_fee(rule, D("74.87")) == D("4.44")  # 0.70 + 3.7435 → half-up 4.44
        assert compute_fee(rule, D("10.10")) == D("1.21")  # 0.70 + 0.505 → 1.205 → 1.21

    def test_tiers_are_marginal(self):
        rule = FeeRule.model_validate(
            {"tiers": [{"up_to": "100", "percent": "0.10"}, {"up_to": None, "percent": "0.05"}]}
        )
        assert variable_fee(rule, D("50")) == D("5.00")
        assert variable_fee(rule, D("150")) == D("12.50")  # 10 + 2.50

    def test_min_max_clamp(self):
        rule = FeeRule.model_validate({"percent": "0.10", "min_fee": "1.00", "max_fee": "20.00"})
        assert compute_fee(rule, D("5")) == D("1.00")
        assert compute_fee(rule, D("500")) == D("20.00")

    def test_zero_percent_selling_fee(self):
        assert compute_fee(FEES.selling_channels["vinted"].selling_fee, D("110")) == 0

    @given(money, money)
    def test_fees_are_monotone(self, a, b):
        rule = FeeRule.model_validate(
            {
                "fixed": "0.30",
                "tiers": [{"up_to": "50", "percent": "0.12"}, {"up_to": None, "percent": "0.03"}],
                "max_fee": "40",
            }
        )
        lo, hi = min(a, b), max(a, b)
        assert compute_fee(rule, lo) <= compute_fee(rule, hi)


class TestWorkedExample:
    """Buy at £45.00, resell at £110.00, default (placeholder) Vinted fees."""

    def test_breakdown(self):
        b = profit_breakdown(D("45.00"), D("110.00"), FEES)
        assert b.acquisition.buyer_fee == D("2.95")
        assert b.acquisition.inbound_shipping == D("2.99")
        assert b.acquisition.total == D("50.94")
        assert b.selling.expected_refunds == D("2.20")
        assert b.selling.total == D("2.70")  # packaging 0.50 + refunds 2.20
        assert b.net_proceeds == D("107.30")
        assert b.net_profit == D("56.36")
        assert b.roi.quantize(D("0.0001")) == D("1.1064")

    def test_max_purchase_price_with_penny_correction(self):
        result = max_purchase_price(
            D("110.00"), FEES, min_profit=D("25"), min_roi=D("0.30"),
            price_cap=D("300"), capital_cap=D("320"), extras=NO_EXTRAS,
        )  # fmt: skip
        # Closed form gives 74.86; fee rounding lets 74.87 still meet the £25 minimum exactly.
        assert result.price == D("74.87")
        assert result.binding == "min_profit"
        assert result.method == "closed_form"
        at_max = profit_breakdown(result.price, D("110.00"), FEES)
        assert at_max.net_profit == D("25.00")
        assert profit_breakdown(result.price + D("0.01"), D("110.00"), FEES).net_profit < D(25)

    def test_roi_can_bind(self):
        result = max_purchase_price(
            D("60.00"), FEES, min_profit=D("5"), min_roi=D("0.50"),
            price_cap=D("300"), capital_cap=None, extras=NO_EXTRAS,
        )  # fmt: skip
        assert result.binding == "min_roi"
        roi = profit_breakdown(result.price, D("60.00"), FEES).roi
        assert roi >= D("0.50")
        assert profit_breakdown(result.price + D("0.01"), D("60.00"), FEES).roi < D("0.50")

    def test_price_cap_binds(self):
        result = max_purchase_price(
            D("1000.00"), FEES, min_profit=D("25"), min_roi=None,
            price_cap=D("300"), capital_cap=None, extras=NO_EXTRAS,
        )  # fmt: skip
        assert (result.price, result.binding) == (D("300.00"), "price_cap")

    def test_capital_cap_binds(self):
        result = max_purchase_price(
            D("1000.00"), FEES, min_profit=D("25"), min_roi=None,
            price_cap=D("900"), capital_cap=D("200"), extras=NO_EXTRAS,
        )  # fmt: skip
        assert result.binding == "capital_cap"
        assert profit_breakdown(result.price, D("1000"), FEES).acquisition.total <= D(200)

    def test_no_viable_price(self):
        result = max_purchase_price(
            D("20.00"), FEES, min_profit=D("25"), min_roi=D("0.3"),
            price_cap=D("300"), capital_cap=None, extras=NO_EXTRAS,
        )  # fmt: skip
        assert result.price is None
        assert "no viable purchase price" in result.note

    def test_extras_reduce_max_price(self):
        base = max_purchase_price(
            D("110"), FEES, min_profit=D("25"), min_roi=None, price_cap=D("300"),
            capital_cap=None, extras=NO_EXTRAS,
        )  # fmt: skip
        with_cleaning = max_purchase_price(
            D("110"), FEES, min_profit=D("25"), min_roi=None, price_cap=D("300"),
            capital_cap=None, extras=Extras(cleaning=D("5.00")),
        )  # fmt: skip
        assert with_cleaning.price < base.price


def _tiered_fees() -> FeesConfig:
    data = FEES.model_dump(mode="json")
    data["purchase_channels"]["vinted"]["buyer_fee"] = {
        "fixed": "0.50",
        "tiers": [{"up_to": "50", "percent": "0.08"}, {"up_to": None, "percent": "0.03"}],
        "max_fee": "15.00",
    }
    return FeesConfig.model_validate(data)


class TestProperties:
    @settings(max_examples=150)
    @given(
        resale=st.decimals(min_value=10, max_value=1500, places=2),
        min_profit=st.decimals(min_value=0, max_value=100, places=2),
        min_roi=st.one_of(st.none(), st.decimals(min_value=0, max_value=2, places=2)),
    )
    def test_max_price_invariants_linear(self, resale, min_profit, min_roi):
        result = max_purchase_price(
            resale, FEES, min_profit=min_profit, min_roi=min_roi, price_cap=D("5000"),
            capital_cap=None, extras=NO_EXTRAS,
        )  # fmt: skip
        assume(result.price is not None)
        at = profit_breakdown(result.price, resale, FEES)
        assert at.net_profit >= min_profit
        if min_roi is not None:
            assert at.roi >= min_roi
        above = profit_breakdown(result.price + D("0.01"), resale, FEES)
        if result.binding == "min_profit":
            assert above.net_profit < min_profit
        if result.binding == "min_roi":
            assert above.roi < min_roi

    @settings(max_examples=100)
    @given(
        resale=st.decimals(min_value=10, max_value=1500, places=2),
        min_profit=st.decimals(min_value=0, max_value=100, places=2),
    )
    def test_closed_form_matches_search(self, resale, min_profit):
        result = max_purchase_price(
            resale, FEES, min_profit=min_profit, min_roi=None, price_cap=D("5000"),
            capital_cap=None, extras=NO_EXTRAS,
        )  # fmt: skip
        assume(result.price is not None and result.binding == "min_profit")

        def fits(p):
            return profit_breakdown(p, resale, FEES).net_profit >= min_profit

        assert search_price(fits, D("5000")) == result.price

    @settings(max_examples=100)
    @given(
        resale=st.decimals(min_value=10, max_value=1500, places=2),
        min_profit=st.decimals(min_value=0, max_value=100, places=2),
    )
    def test_tiered_fees_use_exact_search(self, resale, min_profit):
        fees = _tiered_fees()
        result = max_purchase_price(
            resale, fees, min_profit=min_profit, min_roi=None, price_cap=D("5000"),
            capital_cap=None, extras=NO_EXTRAS,
        )  # fmt: skip
        assume(result.price is not None and result.binding == "min_profit")
        assert result.method == "search"
        assert profit_breakdown(result.price, resale, fees).net_profit >= min_profit
        assert profit_breakdown(result.price + D("0.01"), resale, fees).net_profit < min_profit

    @given(money, money, money)
    def test_max_price_monotone_in_resale(self, a, b, min_profit):
        lo, hi = min(a, b), max(a, b)

        def mp(resale):
            return max_purchase_price(
                resale, FEES, min_profit=min_profit, min_roi=D("0.3"), price_cap=D("5000"),
                capital_cap=None, extras=NO_EXTRAS,
            ).price or D(0)  # fmt: skip

        assert mp(lo) <= mp(hi)

    @given(money, money)
    def test_roi_sign_matches_profit_sign(self, price, resale):
        b = profit_breakdown(price, resale, FEES)
        assert (b.roi > 0) == (b.net_profit > 0)
        assert (b.roi < 0) == (b.net_profit < 0)

    @given(money, money)
    def test_totals_are_exact_sums(self, price, resale):
        b = profit_breakdown(price, resale, FEES)
        lines = b.lines()
        acq = sum(
            D(lines[k])
            for k in (
                "purchase_price",
                "buyer_fee",
                "inbound_shipping",
                "cleaning",
                "repairs",
                "other_acquisition",
            )
        )
        assert acq == b.acquisition.total
        assert b.net_profit == b.net_proceeds - b.acquisition.total
        assert b.acquisition.total.as_tuple().exponent >= -2


@pytest.mark.parametrize("channel", ["ebay"])
def test_unknown_channel_is_an_error(channel):
    with pytest.raises(KeyError):
        profit_breakdown(D(10), D(20), FEES, purchase_channel=channel)
