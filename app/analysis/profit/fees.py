"""Fee schedules.

A fee is ``fixed + variable``, where the variable part is either ``percent × amount`` or a sum
of marginal tiers (each tier's percent applies only to the part of the amount inside its band,
like tax brackets), then clamped to ``[min_fee, max_fee]`` and rounded half-up to the penny —
the way a marketplace charges it. Every fee function is non-decreasing in the amount, which
the maximum-purchase-price search relies on.
"""

from __future__ import annotations

from decimal import Decimal

from app.config.schemas import FeeRule
from app.core.money import ZERO, round_money


def variable_fee(rule: FeeRule, amount: Decimal) -> Decimal:
    if amount <= 0:
        return ZERO
    if not rule.tiers:
        return amount * rule.percent
    total = ZERO
    lower = ZERO
    for tier in rule.tiers:
        upper = tier.up_to
        if upper is None or amount < upper:
            total += (amount - lower) * tier.percent
            return total
        total += (upper - lower) * tier.percent
        lower = upper
    return total  # amount above the last bounded tier with no open-ended tier: no further fee


def compute_fee(rule: FeeRule, amount: Decimal) -> Decimal:
    """The fee charged on ``amount``, in whole pennies."""
    fee = rule.fixed + variable_fee(rule, amount)
    if rule.min_fee is not None:
        fee = max(fee, rule.min_fee)
    if rule.max_fee is not None:
        fee = min(fee, rule.max_fee)
    return round_money(fee)
