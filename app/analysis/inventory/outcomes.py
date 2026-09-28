"""What actually happened to an item, and how it compares with the prediction.

    net_proceeds  = sale_price + shipping charged to the buyer − selling fees
                    − postage you paid − refunds − other selling costs
    actual_profit = net_proceeds − total cost basis
                    (acquisition share + cleaning + repairs + other costs)
    actual_ROI    = actual_profit / total cost basis
    price_error   = actual sale price − predicted expected sale price   (negative: sold for less)
    price_error_% = price_error / predicted expected sale price
    in range      = predicted quick sale ≤ actual sale price ≤ predicted optimistic sale

A written-off item's outcome is a loss of its whole cost basis (ROI −100 %), with no sale price.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict

from app.core.time import days_between

RATIO = Decimal("0.0001")


class SaleFigures(BaseModel):
    model_config = ConfigDict(frozen=True)

    sale_price: Decimal
    shipping_charged_to_buyer: Decimal = Decimal(0)
    selling_fees: Decimal = Decimal(0)
    outbound_shipping_cost: Decimal = Decimal(0)
    refunds: Decimal = Decimal(0)
    other_selling_costs: Decimal = Decimal(0)

    @property
    def net_proceeds(self) -> Decimal:
        return (
            self.sale_price
            + self.shipping_charged_to_buyer
            - self.selling_fees
            - self.outbound_shipping_cost
            - self.refunds
            - self.other_selling_costs
        )


class Prediction(BaseModel):
    model_config = ConfigDict(frozen=True)

    quick: Decimal | None = None
    expected: Decimal | None = None
    optimistic: Decimal | None = None


class Outcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    actual_sale_price: Decimal | None
    actual_profit: Decimal
    actual_roi: Decimal | None
    actual_days_to_sale: int | None
    price_error: Decimal | None = None
    price_error_pct: Decimal | None = None
    within_range: bool | None = None


def _ratio(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    if denominator <= 0:
        return None
    return (numerator / denominator).quantize(RATIO)


def sale_outcome(
    sale: SaleFigures,
    *,
    cost_basis: Decimal,
    prediction: Prediction,
    started_at: datetime,
    sold_at: datetime,
) -> Outcome:
    """``started_at`` is when the item was listed (else when it was bought)."""
    profit = sale.net_proceeds - cost_basis
    error = error_pct = within = None
    if prediction.expected is not None:
        error = sale.sale_price - prediction.expected
        error_pct = _ratio(error, prediction.expected) if prediction.expected > 0 else None
    if prediction.quick is not None and prediction.optimistic is not None:
        within = prediction.quick <= sale.sale_price <= prediction.optimistic
    return Outcome(
        actual_sale_price=sale.sale_price,
        actual_profit=profit,
        actual_roi=_ratio(profit, cost_basis),
        actual_days_to_sale=max(days_between(started_at, sold_at), 0),
        price_error=error,
        price_error_pct=error_pct,
        within_range=within,
    )


def write_off_outcome(*, cost_basis: Decimal) -> Outcome:
    return Outcome(
        actual_sale_price=None,
        actual_profit=-cost_basis,
        actual_roi=Decimal(-1) if cost_basis > 0 else None,
        actual_days_to_sale=None,
    )
