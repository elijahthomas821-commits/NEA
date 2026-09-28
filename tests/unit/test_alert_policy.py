"""Re-alert policy: when an evaluation produces a message."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.config.schemas import RealertRules
from app.core.enums import AlertMode, AlertPriority, Decision
from app.services.alerts import PreviousAlert, material_price_drop, plan_alert, priority_for

D = Decimal
RULES = RealertRules(min_price_drop_pct=D("0.10"), min_price_drop_abs=D("5"))


def plan(mode, decision, price="45", previous=None):
    return plan_alert(mode, decision, D(price) if price else None, previous, RULES)


def test_priority_mapping():
    assert [priority_for(d) for d in Decision] == [
        AlertPriority.HIGH,
        AlertPriority.NORMAL,
        AlertPriority.REVIEW,
        AlertPriority.INFO,
    ]


@pytest.mark.parametrize("decision", list(Decision))
def test_off_never_sends(decision):
    assert not plan(AlertMode.OFF, decision).send


@pytest.mark.parametrize("decision", list(Decision))
def test_always_sends_every_result(decision):
    result = plan(AlertMode.ALWAYS, decision, previous=PreviousAlert(decision, D(45)))
    assert result.send
    assert result.priority is priority_for(decision)


class TestDeals:
    def test_rejected_is_quiet(self):
        assert not plan(AlertMode.DEALS, Decision.REJECTED).send

    def test_first_alert(self):
        result = plan(AlertMode.DEALS, Decision.REVIEW)
        assert result.send
        assert result.reason == "first alert for this listing"

    def test_better_decision(self):
        previous = PreviousAlert(Decision.REVIEW, D(45))
        assert plan(AlertMode.DEALS, Decision.NORMAL, previous=previous).send
        assert not plan(AlertMode.DEALS, Decision.REVIEW, previous=previous).send

    def test_worse_decision_is_quiet(self):
        previous = PreviousAlert(Decision.HIGH_PRIORITY, D(45))
        assert not plan(AlertMode.DEALS, Decision.NORMAL, previous=previous).send

    @pytest.mark.parametrize(
        ("old", "new", "send"),
        [
            ("100", "90", True),  # £10 and 10%
            ("100", "91", False),  # 9% only
            ("40", "35", True),  # £5 and 12.5%
            ("40", "36", False),  # £4 only
            ("300", "294", False),  # £6 but 2%
            ("100", "110", False),  # a rise
        ],
    )
    def test_price_drop(self, old, new, send):
        previous = PreviousAlert(Decision.NORMAL, D(old))
        assert plan(AlertMode.DEALS, Decision.NORMAL, new, previous).send is send


def test_material_price_drop_needs_both_prices():
    assert not material_price_drop(None, D(10), RULES)
    assert not material_price_drop(D(10), None, RULES)
