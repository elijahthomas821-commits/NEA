"""Inventory lifecycle, bundle cost allocation and sale outcomes."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from itertools import pairwise

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.analysis.inventory.lifecycle import (
    EXITS,
    FINAL,
    IN_STOCK,
    SELLABLE,
    TRANSITIONS,
    TransitionError,
    can_sell,
    check_transition,
)
from app.analysis.inventory.outcomes import (
    Prediction,
    SaleFigures,
    sale_outcome,
    write_off_outcome,
)
from app.analysis.profit.allocation import allocate
from app.core.enums import InventoryStatus as S

D = Decimal


class TestLifecycle:
    def test_happy_path(self):
        path = [S.ORDERED, S.IN_TRANSIT, S.RECEIVED, S.NEEDS_WORK, S.READY_TO_LIST, S.LISTED]
        for current, target in pairwise(path):
            check_transition(current, target)

    def test_sold_only_by_recording_a_sale(self):
        with pytest.raises(TransitionError, match="record the sale"):
            check_transition(S.LISTED, S.SOLD)
        assert can_sell(S.LISTED)
        assert not can_sell(S.ORDERED)

    @pytest.mark.parametrize("final", sorted(FINAL))
    def test_final_states(self, final):
        assert TRANSITIONS[final] == frozenset()
        with pytest.raises(TransitionError, match="can't become"):
            check_transition(final, S.LISTED)

    def test_messages(self):
        with pytest.raises(TransitionError, match="already listed"):
            check_transition(S.LISTED, S.LISTED)
        with pytest.raises(TransitionError, match="it can go to: completed, shipped"):
            check_transition(S.SOLD, S.LISTED)

    def test_every_status_is_covered(self):
        assert set(TRANSITIONS) == set(S)
        assert SELLABLE <= IN_STOCK
        assert not IN_STOCK & EXITS
        for status in SELLABLE:
            assert S.SOLD in TRANSITIONS[status]


class TestAllocation:
    def test_proportional(self):
        assert allocate(D("100.00"), [D(90), D(60), D(30)]) == [D("50.00"), D("33.33"), D("16.67")]

    def test_equal_and_leftover_pennies(self):
        assert allocate(D("10.00"), [D(1)] * 3) == [D("3.34"), D("3.33"), D("3.33")]
        assert allocate(D("0.02"), [D(1)] * 3) == [D("0.01"), D("0.01"), D("0.00")]

    def test_zero_weights_split_equally(self):
        assert allocate(D("9.00"), [D(0), D(0), D(0)]) == [D("3.00")] * 3
        assert allocate(D("9.00"), [D(0), D(1)]) == [D("0.00"), D("9.00")]

    @pytest.mark.parametrize(
        ("total", "weights", "message"),
        [
            (D("-1"), [D(1)], "whole pennies"),
            (D("1.001"), [D(1)], "whole pennies"),
            (D(1), [], "nothing to allocate"),
            (D(1), [D(-1), D(2)], "negative"),
        ],
    )
    def test_invalid(self, total, weights, message):
        with pytest.raises(ValueError, match=message):
            allocate(total, weights)

    @given(
        pennies=st.integers(min_value=0, max_value=10_000_000),
        weights=st.lists(
            st.decimals(min_value=0, max_value=10_000, places=2), min_size=1, max_size=12
        ),
    )
    def test_shares_add_up_and_stay_within_a_penny(self, pennies, weights):
        total = D(pennies) / 100
        shares = allocate(total, weights)
        assert sum(shares, D(0)) == total
        assert all(s >= 0 for s in shares)
        weight_sum = sum(weights, D(0))
        effective = weights if weight_sum > 0 else [D(1)] * len(weights)
        effective_sum = sum(effective, D(0))
        for share, weight in zip(shares, effective, strict=True):
            assert abs(share - total * weight / effective_sum) < D("0.01")


class TestOutcomes:
    START = datetime(2026, 9, 4, 10, tzinfo=UTC)
    SOLD = datetime(2026, 9, 14, 9, tzinfo=UTC)

    def test_sale(self):
        sale = SaleFigures(
            sale_price=D("60.00"),
            shipping_charged_to_buyer=D("3.00"),
            selling_fees=D("1.50"),
            outbound_shipping_cost=D("3.00"),
            refunds=D("0"),
            other_selling_costs=D("0.50"),
        )
        assert sale.net_proceeds == D("58.00")
        outcome = sale_outcome(
            sale,
            cost_basis=D("35.00"),
            prediction=Prediction(quick=D(55), expected=D(65), optimistic=D(75)),
            started_at=self.START,
            sold_at=self.SOLD,
        )
        assert outcome.actual_profit == D("23.00")
        assert outcome.actual_roi == D("0.6571")
        assert outcome.actual_days_to_sale == 10
        assert (outcome.price_error, outcome.price_error_pct) == (D("-5.00"), D("-0.0769"))
        assert outcome.within_range is True

    def test_sale_without_prediction(self):
        outcome = sale_outcome(
            SaleFigures(sale_price=D(10)),
            cost_basis=D(0),
            prediction=Prediction(),
            started_at=self.SOLD,
            sold_at=self.START,  # out of order: days never negative
        )
        assert outcome.actual_roi is None
        assert outcome.price_error is None
        assert outcome.within_range is None
        assert outcome.actual_days_to_sale == 0

    def test_write_off(self):
        outcome = write_off_outcome(cost_basis=D("28.00"))
        assert (outcome.actual_profit, outcome.actual_roi, outcome.actual_sale_price) == (
            D("-28.00"),
            D(-1),
            None,
        )
        assert write_off_outcome(cost_basis=D(0)).actual_roi is None
