"""Maximum purchase price: the most you can pay and still meet every target.

The largest price P, in whole pennies (rounded *down*), such that all of these hold:

    (a) profit(P)                 ≥ min_profit
    (b) ROI(P)                    ≥ min_roi              (if configured)
    (c) P                         ≤ max_purchase_price   (hard cap)
    (d) total_acquisition_cost(P) ≤ max_capital_per_item

Net proceeds N do not depend on P, and cost(P) is non-decreasing in P, so (a), (b) and (d) are
all upper bounds on cost(P):

    cost(P) ≤ C = min(N − min_profit,  N / (1 + min_roi),  max_capital_per_item)

For a linear buyer fee ``fixed + pct·P`` the bound has a closed form

    P ≤ (C − fixed − shipping − extras) / (1 + pct)

which is then corrected to the exact penny (the fee is rounded half-up, so the closed form can
be a penny out either way). For tiered/capped fees an exact binary search over whole pennies
is used; both methods give identical answers for linear fees (tested).
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.analysis.profit.model import Extras, acquisition_costs, selling_costs
from app.config.schemas import FeesConfig, PurchaseChannel
from app.core.money import PENNY, round_down_money

Binding = Literal["min_profit", "min_roi", "price_cap", "capital_cap"]
ONE = Decimal(1)
MAX_CORRECTION_STEPS = 10


class MaxPriceResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    price: Decimal | None
    binding: Binding | None
    resale_basis: Decimal
    net_proceeds: Decimal
    cost_ceiling: Decimal
    method: Literal["closed_form", "search", "none"]
    note: str | None = None


def max_purchase_price(
    resale_basis: Decimal,
    fees: FeesConfig,
    *,
    min_profit: Decimal,
    min_roi: Decimal | None,
    price_cap: Decimal,
    capital_cap: Decimal | None,
    extras: Extras,
    purchase_channel: str | None = None,
    selling_channel: str | None = None,
) -> MaxPriceResult:
    buy = fees.purchase_channels[purchase_channel or fees.default_purchase_channel]
    sell = fees.selling_channels[selling_channel or fees.default_selling_channel]
    net = selling_costs(resale_basis, sell).net_proceeds

    ceilings: list[tuple[Decimal, Binding]] = [(net - min_profit, "min_profit")]
    if min_roi is not None:
        ceilings.append((net / (ONE + min_roi), "min_roi"))
    if capital_cap is not None:
        ceilings.append((capital_cap, "capital_cap"))
    ceiling, binding = min(ceilings, key=lambda item: item[0])

    def cost(price: Decimal) -> Decimal:
        return acquisition_costs(price, buy, extras).total

    def fits(price: Decimal) -> bool:
        return cost(price) <= ceiling

    if not fits(PENNY):
        return MaxPriceResult(
            price=None, binding=binding, resale_basis=resale_basis, net_proceeds=net,
            cost_ceiling=ceiling, method="none",
            note="no viable purchase price: fixed costs alone exceed the target",
        )  # fmt: skip

    cap = round_down_money(price_cap)
    if fits(cap):
        return MaxPriceResult(
            price=cap, binding="price_cap", resale_basis=resale_basis, net_proceeds=net,
            cost_ceiling=ceiling, method="closed_form",
        )  # fmt: skip

    if buy.buyer_fee.is_linear:
        price = closed_form_price(ceiling, buy, extras)
        price = _correct(price, fits, cap)
        method: Literal["closed_form", "search"] = "closed_form"
    else:
        price = search_price(fits, cap)
        method = "search"
    return MaxPriceResult(
        price=price, binding=binding, resale_basis=resale_basis, net_proceeds=net,
        cost_ceiling=ceiling, method=method,
    )  # fmt: skip


def closed_form_price(ceiling: Decimal, channel: PurchaseChannel, extras: Extras) -> Decimal:
    """``(C − fixed − shipping − extras) / (1 + pct)``, rounded down to the penny."""
    shipping = (
        extras.inbound_shipping
        if extras.inbound_shipping is not None
        else channel.default_inbound_shipping
    )
    other = shipping + extras.cleaning + extras.repairs + extras.other
    fee = channel.buyer_fee
    return round_down_money((ceiling - fee.fixed - other) / (ONE + fee.percent))


def _correct(price: Decimal, fits: Callable[[Decimal], bool], cap: Decimal) -> Decimal:
    """Move the closed-form answer to the exact largest fitting penny."""
    steps = 0
    while price > PENNY and not fits(price) and steps < MAX_CORRECTION_STEPS:
        price -= PENNY
        steps += 1
    steps = 0
    while price + PENNY <= cap and fits(price + PENNY) and steps < MAX_CORRECTION_STEPS:
        price += PENNY
        steps += 1
    return max(price, PENNY)


def search_price(fits: Callable[[Decimal], bool], cap: Decimal) -> Decimal:
    """Largest whole-penny price in [0.01, cap] that fits (``fits`` is monotone)."""
    lo, hi = 1, int(cap / PENNY)  # in pennies; lo fits, hi does not
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if fits(Decimal(mid) * PENNY):
            lo = mid
        else:
            hi = mid
    return Decimal(lo) * PENNY
