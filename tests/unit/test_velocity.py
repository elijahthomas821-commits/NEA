from datetime import UTC, datetime, timedelta
from decimal import Decimal

from app.analysis.market.comps import CompSale
from app.analysis.velocity.velocity import (
    VelocityScope,
    estimate_velocity,
    kaplan_meier_median,
    liquidity_label,
    liquidity_score,
)
from app.config.loader import load_default_config
from app.core.enums import ConfigKind, SaleSource

D = Decimal
AS_OF = datetime(2026, 9, 1, tzinfo=UTC)
RULES = load_default_config(ConfigKind.MARKET).velocity  # type: ignore[attr-defined]


def sale(days_to_sale, sold_days_ago=5, i=[0]):  # noqa: B006 - simple id counter
    i[0] += 1
    sold = AS_OF - timedelta(days=sold_days_ago)
    return CompSale(
        id=i[0],
        product_id=1,
        brand_id=1,
        category_id=1,
        price=D(100),
        currency="GBP",
        source=SaleSource.MANUAL_ENTRY,
        sold_at=sold,
        listed_at=sold - timedelta(days=days_to_sale) if days_to_sale is not None else None,
    )


class TestKaplanMeier:
    def test_no_censoring_equals_ordinary_median_step(self):
        obs = [(D(d), True) for d in (2, 4, 6, 8, 10)]
        assert kaplan_meier_median(obs) == D(6)

    def test_censoring_lengthens_median(self):
        sold = [(D(d), True) for d in (3, 5, 7)]
        censored = [(D(d), False) for d in (20, 25, 30)]
        assert kaplan_meier_median(sold) == D(5)
        # S(3)=5/6, S(5)=4/6, S(7)=3/6: unsold stock pushes the median from 5 to 7 days.
        assert kaplan_meier_median(sold + censored) == D(7)
        # With most items still unsold the median is not reached at all.
        assert kaplan_meier_median(sold + censored + [(D(40), False)] * 2) is None

    def test_partial_censoring(self):
        obs = [(D(2), True), (D(4), True), (D(5), False), (D(6), True), (D(9), True)]
        # S(2)=4/5, S(4)=3/5, S(6)=3/5*(1-1/2)=0.3 → median 6
        assert kaplan_meier_median(obs) == D(6)

    def test_empty(self):
        assert kaplan_meier_median([]) is None


class TestVelocity:
    def test_uses_first_scope_with_enough_events(self):
        narrow = VelocityScope(name="product", sales=[sale(5), sale(7)])
        broad = VelocityScope(name="brand+category", sales=[sale(d) for d in (4, 8, 12, 16)])
        result = estimate_velocity([narrow, broad], as_of=AS_OF, rules=RULES)
        assert result.scope == "brand+category"
        assert result.median_days_to_sale == D(8)
        assert result.events == 4

    def test_sales_without_listing_dates_do_not_count(self):
        scope = VelocityScope(name="x", sales=[sale(None) for _ in range(10)])
        assert not estimate_velocity([scope], as_of=AS_OF, rules=RULES).known

    def test_volume_and_sell_through(self):
        sales = [sale(5, sold_days_ago=d) for d in (5, 10, 40, 100)]
        scope = VelocityScope(name="x", sales=sales, active_observed=2)
        result = estimate_velocity([scope], as_of=AS_OF, rules=RULES)
        assert (result.sales_last_30d, result.sales_last_90d) == (2, 3)
        assert result.sell_through == D("0.5")

    def test_liquidity(self):
        fast = liquidity_score(D(5), 30, RULES)
        slow = liquidity_score(D(55), 1, RULES)
        assert fast > slow
        assert liquidity_label(fast, RULES) == "high"
        assert liquidity_label(slow, RULES) == "low"
        assert liquidity_score(None, 10, RULES) is None
        assert liquidity_score(D(200), 0, RULES) == D(0)
