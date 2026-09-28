"""Splitting one amount across several items (bundle purchases), exact to the penny.

Each item gets ``total × weight / Σ weights`` rounded down to the penny; the pennies left over
go one each to the items with the largest remainders (ties: earlier items first). The shares
always add up to the total exactly, and each is within a penny of its exact proportion.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import ROUND_FLOOR, Decimal

PENNY = Decimal("0.01")


def allocate(total: Decimal, weights: Sequence[Decimal]) -> list[Decimal]:
    if not weights:
        raise ValueError("nothing to allocate to")
    if total < 0 or total != total.quantize(PENNY):
        raise ValueError("the total must be a non-negative amount in whole pennies")
    if any(w < 0 for w in weights):
        raise ValueError("weights must not be negative")
    weight_sum = sum(weights, Decimal(0))
    if weight_sum == 0:
        weights = [Decimal(1)] * len(weights)
        weight_sum = Decimal(len(weights))

    pennies = int(total / PENNY)
    exact = [Decimal(pennies) * w / weight_sum for w in weights]
    shares = [int(e.to_integral_value(rounding=ROUND_FLOOR)) for e in exact]
    leftover = pennies - sum(shares)
    by_remainder = sorted(range(len(weights)), key=lambda i: (-(exact[i] - shares[i]), i))
    for i in by_remainder[:leftover]:
        shares[i] += 1
    return [Decimal(s) * PENNY for s in shares]
