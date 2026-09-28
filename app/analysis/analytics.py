"""Business metrics from your purchases, stock and sales (pure; see docs/analytics.md).

Everything is computed from simple per-item records so the numbers can be checked by hand.
Money totals are exact sums; averages are rounded half-up to the penny; ratios keep four
decimal places. Dates are compared as UTC calendar days, both ends of a period inclusive.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal
from statistics import median

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.inventory.lifecycle import IN_STOCK
from app.core.enums import InventoryStatus
from app.core.time import days_between, ensure_aware

ZERO = Decimal(0)
PENNY = Decimal("0.01")
RATIO = Decimal("0.0001")
AGE_BUCKETS: list[tuple[str, int, int | None]] = [
    ("0-30", 0, 30),
    ("31-60", 31, 60),
    ("61-90", 61, 90),
    ("90+", 91, None),
]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class Period(_Frozen):
    start: date | None = None
    end: date | None = None

    def contains(self, moment: datetime | None) -> bool:
        if moment is None:
            return False
        day = ensure_aware(moment).date()
        return (self.start is None or day >= self.start) and (self.end is None or day <= self.end)


class ItemRecord(_Frozen):
    item_id: int
    status: InventoryStatus
    purchased_at: datetime
    acquisition_cost: Decimal  # this item's share of the purchase
    extra_costs: Decimal = ZERO  # cleaning + repairs + other
    exit_at: datetime | None = None  # sold, returned or written off
    listed_at: datetime | None = None
    brand: str | None = None
    category: str | None = None
    decision: str | None = None  # the evaluation's decision when you bought it
    comp_level: str | None = None
    expected_resale_price: Decimal | None = None
    sold_at: datetime | None = None
    sale_price: Decimal | None = None
    net_proceeds: Decimal | None = None

    @property
    def cost_basis(self) -> Decimal:
        return self.acquisition_cost + self.extra_costs

    @property
    def is_sold(self) -> bool:
        return self.sold_at is not None and self.net_proceeds is not None

    @property
    def profit(self) -> Decimal | None:
        return self.net_proceeds - self.cost_basis if self.net_proceeds is not None else None

    def in_stock_on(self, day: date) -> bool:
        if ensure_aware(self.purchased_at).date() > day:
            return False
        return self.exit_at is None or ensure_aware(self.exit_at).date() > day


class PredictionRecord(_Frozen):
    comp_level: str | None = None
    from_price_guide: bool = False
    predicted_quick: Decimal | None = None
    predicted_expected: Decimal | None = None
    predicted_optimistic: Decimal | None = None
    predicted_profit: Decimal | None = None
    predicted_days: Decimal | None = None
    actual_sale_price: Decimal | None = None
    actual_profit: Decimal | None = None
    actual_days: int | None = None
    resolved_at: datetime | None = None


# --------------------------------------------------------------------------- helpers


def _money(value: Decimal) -> Decimal:
    return value.quantize(PENNY, rounding=ROUND_HALF_UP)


def _ratio(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    return (numerator / denominator).quantize(RATIO) if denominator > 0 else None


def _mean(values: list[Decimal]) -> Decimal | None:
    return sum(values, ZERO) / len(values) if values else None


def _mean_money(values: list[Decimal]) -> Decimal | None:
    mean = _mean(values)
    return _money(mean) if mean is not None else None


def _mean_days(values: list[int]) -> Decimal | None:
    if not values:
        return None
    return (Decimal(sum(values)) / len(values)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)


def _median_money(values: list[Decimal]) -> Decimal | None:
    return _money(Decimal(median(values))) if values else None


def _median_days(values: list[int]) -> Decimal | None:
    return Decimal(str(median(values))).quantize(Decimal("0.1")) if values else None


# --------------------------------------------------------------------------- sales & P&L


class SalesMetrics(_Frozen):
    items_sold: int = 0
    revenue: Decimal = ZERO
    net_proceeds: Decimal = ZERO
    cost_of_sold: Decimal = ZERO
    realised_profit: Decimal = ZERO
    roi: Decimal | None = None
    margin: Decimal | None = None
    average_profit: Decimal | None = None
    median_profit: Decimal | None = None
    win_rate: Decimal | None = None
    average_days_to_sell: Decimal | None = None  # bought → sold
    median_days_listed_to_sold: Decimal | None = None


def sales_metrics(items: Iterable[ItemRecord]) -> SalesMetrics:
    sold = [i for i in items if i.is_sold]
    if not sold:
        return SalesMetrics()
    profits = [i.profit for i in sold if i.profit is not None]
    revenue = sum((i.sale_price or ZERO for i in sold), ZERO)
    net = sum((i.net_proceeds or ZERO for i in sold), ZERO)
    cost = sum((i.cost_basis for i in sold), ZERO)
    profit = net - cost
    to_sell = [days_between(i.purchased_at, i.sold_at) for i in sold if i.sold_at]
    listed = [days_between(i.listed_at, i.sold_at) for i in sold if i.listed_at and i.sold_at]
    return SalesMetrics(
        items_sold=len(sold),
        revenue=revenue,
        net_proceeds=net,
        cost_of_sold=cost,
        realised_profit=profit,
        roi=_ratio(profit, cost),
        margin=_ratio(profit, revenue),
        average_profit=_mean_money(profits),
        median_profit=_median_money(profits),
        win_rate=_ratio(Decimal(sum(1 for p in profits if p > 0)), Decimal(len(profits))),
        average_days_to_sell=_mean_days(to_sell),
        median_days_listed_to_sold=_median_days(listed),
    )


class Summary(_Frozen):
    period: Period
    items_bought: int
    spend: Decimal  # acquisition cost of items bought in the period
    sales: SalesMetrics
    written_off: int
    write_off_loss: Decimal
    returned: int
    return_loss: Decimal  # cleaning/repairs/other on items sent back (the purchase is refunded)
    net_result: Decimal  # realised profit − write-off loss − return loss
    sell_through: Decimal | None  # sold ÷ (sold + still in stock at the end of the period)


def summarise(items: list[ItemRecord], period: Period, *, today: date) -> Summary:
    bought = [i for i in items if period.contains(i.purchased_at)]
    sold = [i for i in items if i.is_sold and period.contains(i.sold_at)]
    written = [
        i for i in items if i.status is InventoryStatus.WRITTEN_OFF and period.contains(i.exit_at)
    ]
    returned = [
        i for i in items if i.status is InventoryStatus.RETURNED and period.contains(i.exit_at)
    ]
    sales = sales_metrics(sold)
    write_off_loss = sum((i.cost_basis for i in written), ZERO)
    return_loss = sum((i.extra_costs for i in returned), ZERO)
    end = period.end or today
    in_stock_at_end = sum(1 for i in items if i.in_stock_on(end))
    return Summary(
        period=period,
        items_bought=len(bought),
        spend=sum((i.acquisition_cost for i in bought), ZERO),
        sales=sales,
        written_off=len(written),
        write_off_loss=write_off_loss,
        returned=len(returned),
        return_loss=return_loss,
        net_result=sales.realised_profit - write_off_loss - return_loss,
        sell_through=_ratio(Decimal(len(sold)), Decimal(len(sold) + in_stock_at_end)),
    )


# --------------------------------------------------------------------------- breakdowns


class BreakdownRow(_Frozen):
    key: str
    sales: SalesMetrics


BREAKDOWNS: dict[str, Callable[[ItemRecord], str | None]] = {
    "brand": lambda i: i.brand,
    "category": lambda i: i.category,
    "month": lambda i: f"{ensure_aware(i.sold_at):%Y-%m}" if i.sold_at else None,
    "decision": lambda i: i.decision,
    "comp_level": lambda i: i.comp_level,
}


def breakdown(items: list[ItemRecord], period: Period, by: str) -> list[BreakdownRow]:
    """Sales in the period grouped by ``brand``, ``category``, ``month``, ``decision`` or
    ``comp_level`` (items with no value are grouped as ``unknown``). Best profit first."""
    key_of = BREAKDOWNS[by]
    groups: dict[str, list[ItemRecord]] = {}
    for item in items:
        if item.is_sold and period.contains(item.sold_at):
            groups.setdefault(key_of(item) or "unknown", []).append(item)
    rows = [BreakdownRow(key=k, sales=sales_metrics(v)) for k, v in groups.items()]
    if by == "month":
        return sorted(rows, key=lambda r: r.key)
    return sorted(rows, key=lambda r: (-r.sales.realised_profit, r.key))


# --------------------------------------------------------------------------- stock


class StockAgeing(_Frozen):
    bucket: str
    items: int
    capital: Decimal


class StockSnapshot(_Frozen):
    as_of: date
    items: int
    capital: Decimal  # total cost basis tied up
    expected_value: Decimal  # sum of expected resale prices, where known (an estimate)
    items_without_estimate: int
    by_status: dict[str, int] = Field(default_factory=dict)
    ageing: list[StockAgeing] = Field(default_factory=list)  # days since purchase
    listed_items: int = 0
    average_days_listed: Decimal | None = None


def stock_snapshot(items: list[ItemRecord], *, today: date) -> StockSnapshot:
    stock = [i for i in items if i.status in IN_STOCK]
    by_status: dict[str, int] = {}
    for item in stock:
        by_status[item.status.value] = by_status.get(item.status.value, 0) + 1
    ageing = []
    for label, low, high in AGE_BUCKETS:
        members = [
            i
            for i in stock
            if low <= days_between(i.purchased_at, today)
            and (high is None or days_between(i.purchased_at, today) <= high)
        ]
        ageing.append(
            StockAgeing(
                bucket=label,
                items=len(members),
                capital=sum((i.cost_basis for i in members), ZERO),
            )
        )
    listed = [i for i in stock if i.status is InventoryStatus.LISTED and i.listed_at]
    return StockSnapshot(
        as_of=today,
        items=len(stock),
        capital=sum((i.cost_basis for i in stock), ZERO),
        expected_value=sum(
            (i.expected_resale_price for i in stock if i.expected_resale_price is not None), ZERO
        ),
        items_without_estimate=sum(1 for i in stock if i.expected_resale_price is None),
        by_status=dict(sorted(by_status.items())),
        ageing=ageing,
        listed_items=len(listed),
        average_days_listed=_mean_days(
            [days_between(i.listed_at, today) for i in listed if i.listed_at]
        ),
    )


# --------------------------------------------------------------------------- predictions


class AccuracyMetrics(_Frozen):
    resolved: int = 0
    mean_absolute_error: Decimal | None = None  # sale price, money
    mean_absolute_pct_error: Decimal | None = None
    bias: Decimal | None = None  # mean (actual − predicted): negative means overestimating
    within_range_share: Decimal | None = None  # quick ≤ actual ≤ optimistic
    mean_profit_error: Decimal | None = None
    mean_days_error: Decimal | None = None


class AccuracyReport(_Frozen):
    overall: AccuracyMetrics
    by_comp_level: dict[str, AccuracyMetrics]
    by_basis: dict[str, AccuracyMetrics]  # "comps" vs "price_guide"


class _Resolved(_Frozen):
    actual: Decimal
    expected: Decimal
    quick: Decimal | None
    optimistic: Decimal | None
    profit_error: Decimal | None
    days_error: Decimal | None


def _resolved(record: PredictionRecord) -> _Resolved | None:
    if (
        record.resolved_at is None
        or record.actual_sale_price is None
        or record.predicted_expected is None
    ):
        return None
    profit_error = (
        record.actual_profit - record.predicted_profit
        if record.actual_profit is not None and record.predicted_profit is not None
        else None
    )
    days_error = (
        Decimal(record.actual_days) - record.predicted_days
        if record.actual_days is not None and record.predicted_days is not None
        else None
    )
    return _Resolved(
        actual=record.actual_sale_price,
        expected=record.predicted_expected,
        quick=record.predicted_quick,
        optimistic=record.predicted_optimistic,
        profit_error=profit_error,
        days_error=days_error,
    )


def accuracy_metrics(records: Iterable[PredictionRecord]) -> AccuracyMetrics:
    """Sold items only (a write-off has no sale price to compare)."""
    sold = [r for r in (_resolved(rec) for rec in records) if r is not None]
    if not sold:
        return AccuracyMetrics()
    errors = [r.actual - r.expected for r in sold]
    pct = [abs(r.actual - r.expected) / r.expected for r in sold if r.expected > 0]
    ranged = [
        (r.quick, r.actual, r.optimistic)
        for r in sold
        if r.quick is not None and r.optimistic is not None
    ]
    within = sum(1 for quick, actual, optimistic in ranged if quick <= actual <= optimistic)
    profit_errors = [r.profit_error for r in sold if r.profit_error is not None]
    day_errors = [r.days_error for r in sold if r.days_error is not None]
    mape = _mean(pct)
    days = _mean(day_errors)
    return AccuracyMetrics(
        resolved=len(sold),
        mean_absolute_error=_mean_money([abs(e) for e in errors]),
        mean_absolute_pct_error=mape.quantize(RATIO) if mape is not None else None,
        bias=_mean_money(errors),
        within_range_share=_ratio(Decimal(within), Decimal(len(ranged))),
        mean_profit_error=_mean_money(profit_errors),
        mean_days_error=(
            days.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP) if days is not None else None
        ),
    )


def accuracy_report(records: list[PredictionRecord], period: Period) -> AccuracyReport:
    in_period = [r for r in records if period.contains(r.resolved_at)]
    levels: dict[str, list[PredictionRecord]] = {}
    bases: dict[str, list[PredictionRecord]] = {}
    for r in in_period:
        levels.setdefault(r.comp_level or "unknown", []).append(r)
        bases.setdefault("price_guide" if r.from_price_guide else "comps", []).append(r)
    return AccuracyReport(
        overall=accuracy_metrics(in_period),
        by_comp_level={k: accuracy_metrics(v) for k, v in sorted(levels.items())},
        by_basis={k: accuracy_metrics(v) for k, v in sorted(bases.items())},
    )
