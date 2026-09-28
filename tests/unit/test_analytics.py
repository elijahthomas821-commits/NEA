"""Analytics reconcile with hand-computed numbers (docs/analytics.md, worked example)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from app.analysis.analytics import (
    ItemRecord,
    Period,
    PredictionRecord,
    accuracy_metrics,
    accuracy_report,
    breakdown,
    sales_metrics,
    stock_snapshot,
    summarise,
)
from app.core.enums import InventoryStatus as S

D = Decimal
SEPTEMBER = Period(start=date(2026, 9, 1), end=date(2026, 9, 30))
TODAY = date(2026, 10, 5)


def at(month: int, day: int) -> datetime:
    return datetime(2026, month, day, 12, tzinfo=UTC)


# The worked example: nine items.
ITEMS = [
    ItemRecord(  # A: bought in August, sold in September
        item_id=1, status=S.COMPLETED, purchased_at=at(8, 20), acquisition_cost=D("50.94"),
        listed_at=at(8, 25), sold_at=at(9, 5), exit_at=at(9, 5), sale_price=D("110.00"),
        net_proceeds=D("107.30"), brand="Stone Island", category="Sweatshirts",
        decision="high_priority", comp_level="L2",
    ),
    ItemRecord(  # B: £5 cleaning
        item_id=2, status=S.SHIPPED, purchased_at=at(9, 2), acquisition_cost=D("30.00"),
        extra_costs=D("5.00"), listed_at=at(9, 4), sold_at=at(9, 14), exit_at=at(9, 14),
        sale_price=D("60.00"), net_proceeds=D("57.00"), brand="CP Company", category="Jackets",
        decision="normal", comp_level="L4",
    ),
    ItemRecord(  # C: sold at a loss
        item_id=3, status=S.SOLD, purchased_at=at(9, 3), acquisition_cost=D("80.00"),
        listed_at=at(9, 6), sold_at=at(9, 26), exit_at=at(9, 26), sale_price=D("70.00"),
        net_proceeds=D("68.00"), brand="Stone Island", category="Jackets", decision="review",
        comp_level="L5",
    ),
    ItemRecord(  # D: listed, unsold
        item_id=4, status=S.LISTED, purchased_at=at(9, 10), acquisition_cost=D("40.00"),
        listed_at=at(9, 12), expected_resale_price=D("90.00"),
    ),
    ItemRecord(  # E: written off
        item_id=5, status=S.WRITTEN_OFF, purchased_at=at(9, 15), acquisition_cost=D("25.00"),
        extra_costs=D("3.00"), exit_at=at(9, 20),
    ),
    ItemRecord(  # F: returned to the seller; £2 of extras are lost
        item_id=6, status=S.RETURNED, purchased_at=at(9, 18), acquisition_cost=D("45.00"),
        extra_costs=D("2.00"), exit_at=at(9, 22),
    ),
    ItemRecord(  # G: old stock, no estimate
        item_id=7, status=S.LISTED, purchased_at=at(6, 1), acquisition_cost=D("60.00"),
        listed_at=at(6, 10),
    ),
    ItemRecord(  # H: just ordered
        item_id=8, status=S.ORDERED, purchased_at=at(9, 28), acquisition_cost=D("35.00"),
        expected_resale_price=D("70.00"),
    ),
    ItemRecord(  # I: bought in September, sold in October
        item_id=9, status=S.COMPLETED, purchased_at=at(9, 5), acquisition_cost=D("20.00"),
        sold_at=at(10, 2), exit_at=at(10, 2), sale_price=D("50.00"), net_proceeds=D("49.00"),
    ),
]  # fmt: skip


def test_summary_worked_example():
    s = summarise(ITEMS, SEPTEMBER, today=TODAY)
    assert (s.items_bought, s.spend) == (7, D("275.00"))  # B C D E F H I
    sales = s.sales
    assert sales.items_sold == 3  # A B C
    assert (sales.revenue, sales.net_proceeds, sales.cost_of_sold) == (
        D("240.00"),
        D("232.30"),
        D("165.94"),
    )
    assert sales.realised_profit == D("66.36")
    assert (sales.roi, sales.margin) == (D("0.3999"), D("0.2765"))
    assert (sales.average_profit, sales.median_profit) == (D("22.12"), D("22.00"))
    assert sales.win_rate == D("0.6667")
    assert sales.average_days_to_sell == D("17.0")  # 16, 12, 23
    assert sales.median_days_listed_to_sold == D("11.0")  # 11, 10, 20
    assert (s.written_off, s.write_off_loss) == (1, D("28.00"))
    assert (s.returned, s.return_loss) == (1, D("2.00"))
    assert s.net_result == D("36.36")
    assert s.sell_through == D("0.4286")  # 3 sold ÷ (3 + D G H I in stock on 30 Sep)


def test_stock_worked_example():
    stock = stock_snapshot(ITEMS, today=TODAY)
    assert (stock.items, stock.capital) == (3, D("135.00"))  # D G H
    assert (stock.expected_value, stock.items_without_estimate) == (D("160.00"), 1)
    assert stock.by_status == {"listed": 2, "ordered": 1}
    assert [(a.bucket, a.items, a.capital) for a in stock.ageing] == [
        ("0-30", 2, D("75.00")),
        ("31-60", 0, D("0")),
        ("61-90", 0, D("0")),
        ("90+", 1, D("60.00")),
    ]
    assert (stock.listed_items, stock.average_days_listed) == (2, D("70.0"))  # 23 and 117


def test_breakdowns():
    by_brand = breakdown(ITEMS, SEPTEMBER, "brand")
    assert [(r.key, r.sales.items_sold, r.sales.realised_profit) for r in by_brand] == [
        ("Stone Island", 2, D("44.36")),
        ("CP Company", 1, D("22.00")),
    ]
    by_decision = breakdown(ITEMS, SEPTEMBER, "decision")
    assert [(r.key, r.sales.realised_profit) for r in by_decision] == [
        ("high_priority", D("56.36")),
        ("normal", D("22.00")),
        ("review", D("-12.00")),
    ]
    assert [r.key for r in breakdown(ITEMS, Period(), "month")] == ["2026-09", "2026-10"]
    all_time = breakdown(ITEMS, Period(), "brand")
    assert ("unknown", 1) in [(r.key, r.sales.items_sold) for r in all_time]  # item I
    assert [r.key for r in breakdown(ITEMS, SEPTEMBER, "category")] == ["Sweatshirts", "Jackets"]


def test_empty_inputs():
    assert sales_metrics([]).items_sold == 0
    empty = summarise([], SEPTEMBER, today=TODAY)
    assert (empty.sell_through, empty.sales.roi, empty.net_result) == (None, None, D(0))
    assert stock_snapshot([], today=TODAY).average_days_listed is None
    assert breakdown([], SEPTEMBER, "brand") == []


def test_period_bounds_are_inclusive_days():
    period = Period(start=date(2026, 9, 5), end=date(2026, 9, 5))
    assert period.contains(datetime(2026, 9, 5, 0, 0, tzinfo=UTC))
    assert period.contains(datetime(2026, 9, 5, 23, 59, tzinfo=UTC))
    assert not period.contains(datetime(2026, 9, 6, 0, 0, tzinfo=UTC))
    assert not period.contains(None)
    assert Period().contains(at(1, 1))


PREDICTIONS = [
    PredictionRecord(  # A: spot on
        comp_level="L2", predicted_quick=D(95), predicted_expected=D(110),
        predicted_optimistic=D(125), predicted_profit=D("56.36"), predicted_days=D(9),
        actual_sale_price=D(110), actual_profit=D("56.36"), actual_days=11, resolved_at=at(9, 5),
    ),
    PredictionRecord(  # B: £5 under, inside the range
        comp_level="L4", predicted_quick=D(55), predicted_expected=D(65),
        predicted_optimistic=D(75), predicted_profit=D(25), predicted_days=D(10),
        actual_sale_price=D(60), actual_profit=D(22), actual_days=10, resolved_at=at(9, 14),
    ),
    PredictionRecord(  # C: £30 under, outside the range
        comp_level="L5", predicted_quick=D(85), predicted_expected=D(100),
        predicted_optimistic=D(115), predicted_profit=D(8), predicted_days=D(14),
        actual_sale_price=D(70), actual_profit=D(-12), actual_days=20, resolved_at=at(9, 26),
    ),
    PredictionRecord(  # E: a write-off has no sale price to compare
        comp_level="GUIDE", from_price_guide=True, predicted_expected=D(60),
        predicted_profit=D(20), actual_profit=D(-28), resolved_at=at(9, 20),
    ),
    PredictionRecord(  # still in stock: unresolved
        comp_level="L2", predicted_expected=D(90),
    ),
]  # fmt: skip


def test_prediction_accuracy_worked_example():
    m = accuracy_metrics(PREDICTIONS)
    assert m.resolved == 3
    assert m.mean_absolute_error == D("11.67")  # (0 + 5 + 30) / 3
    assert m.mean_absolute_pct_error == D("0.1256")  # (0 + 5/65 + 30/100) / 3
    assert m.bias == D("-11.67")  # predictions ran high
    assert m.within_range_share == D("0.6667")
    assert m.mean_profit_error == D("-7.67")  # (0 - 3 - 20) / 3
    assert m.mean_days_error == D("2.7")  # (2 + 0 + 6) / 3


def test_accuracy_report_groups():
    report = accuracy_report(PREDICTIONS, SEPTEMBER)
    assert report.overall.resolved == 3
    assert set(report.by_comp_level) == {"L2", "L4", "L5", "GUIDE"}
    assert report.by_comp_level["GUIDE"].resolved == 0
    assert report.by_basis["comps"].resolved == 3
    assert accuracy_report(PREDICTIONS, Period(start=date(2026, 9, 10))).overall.resolved == 2


@pytest.mark.parametrize("by", ["brand", "category", "month", "decision", "comp_level"])
def test_breakdown_totals_match_the_summary(by):
    rows = breakdown(ITEMS, SEPTEMBER, by)
    total = summarise(ITEMS, SEPTEMBER, today=TODAY).sales
    assert sum(r.sales.items_sold for r in rows) == total.items_sold
    assert sum((r.sales.realised_profit for r in rows), D(0)) == total.realised_profit
