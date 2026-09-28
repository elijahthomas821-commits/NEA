"""Comparable-sales engine and resale estimates."""

from __future__ import annotations

import itertools
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

from app.analysis.market.comps import CompSale, CompTarget, FxTable, estimate_market
from app.analysis.pricing.estimates import estimate_from_guide, estimate_from_market
from app.config.loader import load_default_config
from app.config.schemas import MarketConfig, PriceGuideConfig
from app.core.enums import CompLevel, Condition, ConfigKind, PriceType, SaleSource

D = Decimal
AS_OF = datetime(2026, 9, 1, 12, tzinfo=UTC)
MARKET: MarketConfig = load_default_config(ConfigKind.MARKET)  # type: ignore[assignment]
CONDITIONS = load_default_config(ConfigKind.CONDITIONS)
SIZES = load_default_config(ConfigKind.SIZES)
PRODUCT, OTHER_PRODUCT, GENERIC = 10, 11, 99
BRAND, CATEGORY = 1, 2
_ids = itertools.count(1)


def sale(
    price,
    *,
    days_ago=10,
    product=PRODUCT,
    size="L",
    condition=Condition.VERY_GOOD,
    colour="navy",
    currency="GBP",
    source=SaleSource.MANUAL_ENTRY,
    marketplace="vinted",
    price_type=PriceType.FINAL_SALE_PRICE,
    brand=BRAND,
    category=CATEGORY,
    listed_days=None,
):
    sold_at = AS_OF - timedelta(days=days_ago)
    return CompSale(
        id=next(_ids),
        product_id=product,
        brand_id=brand,
        category_id=category,
        size=size,
        colour=colour,
        condition=condition,
        price=D(str(price)),
        currency=currency,
        price_type=price_type,
        source=source,
        marketplace=marketplace,
        sold_at=sold_at,
        listed_at=sold_at - timedelta(days=listed_days) if listed_days is not None else None,
    )


def target(**overrides) -> CompTarget:
    data = {
        "product_id": PRODUCT,
        "product_is_generic": False,
        "brand_id": BRAND,
        "category_id": CATEGORY,
        "category_slug": "sweatshirts",
        "size": "L",
        "colour": "navy",
        "condition": Condition.VERY_GOOD,
        "currency": "GBP",
        "match_confidence": D("0.9"),
        "as_of": AS_OF,
    }
    data.update(overrides)
    return CompTarget(**data)


def run(t, sales, market=MARKET, fx=None):
    return estimate_market(t, sales, market=market, conditions=CONDITIONS, sizes=SIZES, fx=fx)


class TestLevels:
    def test_exact_matches_use_l1(self):
        result = run(target(), [sale(p) for p in (95, 100, 105, 110, 90, 100)])
        assert result.level is CompLevel.L1
        assert result.sample_size == 6
        assert D(95) <= result.percentiles["p50"] <= D(105)

    def test_falls_back_when_colour_differs(self):
        result = run(target(), [sale(p, colour="black") for p in (95, 100, 105, 110, 90)])
        assert result.level is CompLevel.L2
        assert [a.level for a in result.attempts[:1]] == [CompLevel.L1]
        assert not result.attempts[0].accepted

    def test_other_sizes_are_size_adjusted_at_l3(self):
        comps = [sale(100, size="XXL") for _ in range(6)]
        result = run(target(size="L"), comps)
        assert result.level is CompLevel.L3
        # XXL multiplier 0.92, L 1.00 → £100 XXL comp is worth ~£108.70 for an L.
        assert result.percentiles["p50"].quantize(D("0.01")) == D("108.70")

    def test_condition_adjustment_at_l4(self):
        comps = [sale(85, condition=Condition.GOOD) for _ in range(6)]
        result = run(target(condition=Condition.VERY_GOOD), comps)
        assert result.level is CompLevel.L4
        # 85 × 1.00 / 0.85 = 100 exactly.
        assert result.percentiles["p50"] == D(100)
        assert result.comps[0].condition_ratio.quantize(D("0.0001")) == D("1.1765")

    def test_generic_match_skips_product_levels(self):
        comps = [sale(100, product=OTHER_PRODUCT) for _ in range(6)]
        result = run(target(product_id=GENERIC, product_is_generic=True), comps)
        assert result.level is CompLevel.L5
        assert all(a.level in (CompLevel.L5, CompLevel.L6) for a in result.attempts)

    def test_other_brand_or_category_never_counts(self):
        comps = [sale(100, brand=7, product=None) for _ in range(6)]
        comps += [sale(100, category=8, product=None) for _ in range(6)]
        result = run(target(product_id=None, product_is_generic=True), comps)
        assert not result.has_estimate

    def test_unknown_condition_comps_only_count_where_condition_is_not_required(self):
        comps = [sale(100, condition=None, product=None) for _ in range(8)]
        result = run(target(product_id=None, product_is_generic=True), comps)
        assert result.level is CompLevel.L6
        # Unknown condition is treated as "good" (0.85) and down-weighted.
        assert result.percentiles["p50"].quantize(D("0.01")) == D("117.65")
        assert result.comps[0].trust < D("0.8")


class TestEligibility:
    def test_zero_comps(self):
        result = run(target(), [])
        assert not result.has_estimate
        assert result.level is None
        assert estimate_from_market(result, MARKET.estimate_percentiles) is None

    def test_insufficient_data_is_reported(self):
        result = run(target(), [sale(100), sale(105)])
        assert not result.has_estimate
        assert all(not a.accepted for a in result.attempts)
        assert "min 3" in result.attempts[0].reason

    def test_future_and_old_sales_excluded(self):
        comps = [sale(100, days_ago=-5), sale(100, days_ago=400)]
        result = run(target(), comps)
        reasons = sorted(e.reason for e in result.excluded)
        assert reasons == ["outside the comparison window", "sold after the evaluation time"]

    def test_currency_mismatch_excluded_without_fx(self):
        comps = [sale(100, currency="EUR") for _ in range(6)]
        result = run(target(), comps)
        assert not result.has_estimate
        assert {e.reason for e in result.excluded} == {"no EUR->GBP rate for the sale date"}

    def test_currency_converted_with_fx(self):
        fx = FxTable(rates={FxTable.key("GBP", "EUR"): [(date(2026, 8, 20), D("1.25"))]})
        comps = [sale(125, currency="EUR", days_ago=10) for _ in range(6)]
        result = run(target(), comps, fx=fx)
        assert result.has_estimate
        assert result.percentiles["p50"] == D(100)  # inverse of GBP→EUR 1.25

    def test_stale_fx_rate_not_used(self):
        fx = FxTable(rates={FxTable.key("EUR", "GBP"): [(date(2026, 1, 1), D("0.8"))]})
        result = run(target(), [sale(125, currency="EUR") for _ in range(6)], fx=fx)
        assert not result.has_estimate

    def test_last_asking_price_haircut_and_trust(self):
        comps = [
            sale(
                100, price_type=PriceType.LAST_ASKING_PRICE, source=SaleSource.OBSERVED_SOLD_LISTING
            )
            for _ in range(6)
        ]
        result = run(target(), comps)
        assert result.percentiles["p50"] == D("92.00")
        assert result.comps[0].trust == D("0.7") * D("1.0") * D("0.6")

    def test_last_asking_price_can_be_excluded_from_price(self):
        market = MARKET.model_copy(
            update={
                "last_asking_price": MARKET.last_asking_price.model_copy(
                    update={"use_for_price": False}
                )
            }
        )
        comps = [sale(100, price_type=PriceType.LAST_ASKING_PRICE) for _ in range(6)]
        result = run(target(), comps, market=market)
        assert not result.has_estimate
        assert result.excluded[0].reason == "asking price only (speed data)"


class TestOutliersAndConfidence:
    def test_extreme_prices_flagged_not_deleted(self):
        comps = [sale(p) for p in (95, 100, 105, 98, 102, 5, 2000)]
        result = run(target(), comps)
        assert result.has_estimate
        assert sorted(c.original_price for c in result.outliers) == [D(5), D(2000)]
        assert all(c.is_outlier for c in result.outliers)
        assert D(95) <= result.percentiles["p10"]
        assert result.percentiles["p90"] <= D(105)

    def test_more_data_means_more_confidence(self):
        few = run(target(), [sale(p) for p in (95, 100, 105)])
        many = run(target(), [sale(p) for p in (95, 100, 105) * 6])
        assert many.confidence > few.confidence

    def test_recent_sales_weigh_more(self):
        comps = [sale(100, days_ago=1) for _ in range(6)] + [
            sale(200, days_ago=300) for _ in range(6)
        ]
        result = run(target(), comps)
        assert result.has_estimate
        assert result.percentiles["p50"] < D(150)

    def test_old_sales_reduce_effective_sample_size(self):
        comps = [sale(100, days_ago=1) for _ in range(3)] + [
            sale(200, days_ago=300) for _ in range(3)
        ]
        result = run(target(), comps)
        assert not result.has_estimate  # 6 sales, but effective n < 5
        assert result.attempts[0].sample_size == 6
        assert result.attempts[0].effective_sample_size < D(5)

    def test_broader_level_means_less_confidence(self):
        l1 = run(target(), [sale(100) for _ in range(6)])
        l6 = run(
            target(product_id=None, product_is_generic=True),
            [sale(100, condition=Condition.GOOD, product=None) for _ in range(6)],
        )
        assert l6.level is CompLevel.L6
        assert l1.confidence > l6.confidence

    def test_dispersion(self):
        tight = run(target(), [sale(p) for p in (99, 100, 101, 100, 100, 100)])
        wide = run(target(), [sale(p) for p in (60, 100, 140, 80, 120, 100)])
        assert tight.dispersion < wide.dispersion
        assert tight.confidence > wide.confidence


class TestEstimates:
    def test_estimate_percentiles(self):
        result = run(target(), [sale(p) for p in (80, 90, 100, 110, 120)])
        est = estimate_from_market(result, MARKET.estimate_percentiles)
        assert est.basis == "comps"
        assert est.quick < est.expected < est.optimistic
        assert est.expected == result.percentiles["p50"]
        assert est.level is CompLevel.L1


GUIDE = PriceGuideConfig.model_validate(
    {
        "entries": [
            {
                "brand": "stone-island",
                "category": "sweatshirts",
                "low": "60",
                "typical": "80",
                "high": "100",
            },
            {
                "brand": "stone-island",
                "category": "sweatshirts",
                "product": "crewneck-sweatshirt",
                "condition": "good",
                "low": "70",
                "typical": "85",
                "high": "110",
            },
        ]
    }
)  # fmt: skip


class TestPriceGuide:
    def _guide(self, **kwargs):
        defaults = {
            "brand_slug": "stone-island",
            "category_slug": "sweatshirts",
            "product_slug": None,
            "condition": Condition.VERY_GOOD,
            "size": "L",
            "currency": "GBP",
            "conditions": CONDITIONS,
            "sizes": SIZES,
        }
        defaults.update(kwargs)
        return estimate_from_guide(GUIDE, MARKET.price_guide, **defaults)

    def test_general_entry(self):
        est = self._guide()
        assert est.basis == "price_guide"
        assert est.level is CompLevel.GUIDE
        assert (est.quick, est.expected, est.optimistic) == (D(60), D(80), D(100))
        assert est.confidence == D("0.25")

    def test_product_entry_with_condition_adjustment(self):
        est = self._guide(product_slug="crewneck-sweatshirt")
        # Entry is for "good" (0.85); the listing is "very good" (1.00).
        assert est.expected.quantize(D("0.01")) == D("100.00")

    @pytest.mark.parametrize(
        "override",
        [{"brand_slug": "moncler"}, {"currency": "EUR"}, {"category_slug": None}],
    )
    def test_no_entry(self, override):
        assert self._guide(**override) is None

    def test_disabled(self):
        rules = MARKET.price_guide.model_copy(update={"enabled": False})
        assert estimate_from_guide(
            GUIDE, rules, brand_slug="stone-island", category_slug="sweatshirts",
            product_slug=None, condition=None, size=None, currency="GBP",
            conditions=CONDITIONS, sizes=SIZES,
        ) is None  # fmt: skip
