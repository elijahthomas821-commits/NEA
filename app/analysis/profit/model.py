"""Cost model, profit and ROI.

    total_acquisition_cost = purchase_price + buyer_fee(purchase_price) + inbound_shipping
                           + cleaning + repairs + other_acquisition
    selling_costs(sale)    = selling_fee(sale) + outbound_shipping_paid_by_seller + packaging
                           + expected_refunds(sale) + other_selling
    net_proceeds           = sale_price − selling_costs(sale_price)
    net_profit             = net_proceeds − total_acquisition_cost
    ROI                    = net_profit / total_acquisition_cost

ROI is measured on the total cost of acquiring the item (what you actually risk), not on the
listing price. Individual fees are whole pennies (as charged); totals are exact sums; ratios keep
full precision and are only rounded for display.
"""

from __future__ import annotations

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.profit.fees import compute_fee
from app.config.schemas import FeesConfig, PurchaseChannel, SellingChannel
from app.core.money import ZERO, round_money


class Extras(BaseModel):
    """Per-item costs you expect on top of fees and postage."""

    model_config = ConfigDict(frozen=True)

    inbound_shipping: Decimal | None = None  # None → the channel's default postage
    cleaning: Decimal = ZERO
    repairs: Decimal = ZERO
    other: Decimal = ZERO


class AcquisitionCosts(BaseModel):
    model_config = ConfigDict(frozen=True)

    purchase_price: Decimal
    buyer_fee: Decimal
    inbound_shipping: Decimal
    cleaning: Decimal = ZERO
    repairs: Decimal = ZERO
    other: Decimal = ZERO

    @property
    def total(self) -> Decimal:
        return (
            self.purchase_price
            + self.buyer_fee
            + self.inbound_shipping
            + self.cleaning
            + self.repairs
            + self.other
        )


class SellingCosts(BaseModel):
    model_config = ConfigDict(frozen=True)

    sale_price: Decimal
    selling_fee: Decimal
    outbound_shipping: Decimal
    packaging: Decimal
    expected_refunds: Decimal
    other: Decimal

    @property
    def total(self) -> Decimal:
        return (
            self.selling_fee
            + self.outbound_shipping
            + self.packaging
            + self.expected_refunds
            + self.other
        )

    @property
    def net_proceeds(self) -> Decimal:
        return self.sale_price - self.total


class ProfitBreakdown(BaseModel):
    model_config = ConfigDict(frozen=True)

    acquisition: AcquisitionCosts
    selling: SellingCosts
    currency: str = Field(default="GBP")

    @property
    def net_proceeds(self) -> Decimal:
        return self.selling.net_proceeds

    @property
    def net_profit(self) -> Decimal:
        return self.selling.net_proceeds - self.acquisition.total

    @property
    def roi(self) -> Decimal | None:
        total = self.acquisition.total
        return self.net_profit / total if total > 0 else None

    def lines(self) -> dict[str, str]:
        """Every cost line, for the evaluation record."""
        a, s = self.acquisition, self.selling
        return {
            "purchase_price": str(a.purchase_price),
            "buyer_fee": str(a.buyer_fee),
            "inbound_shipping": str(a.inbound_shipping),
            "cleaning": str(a.cleaning),
            "repairs": str(a.repairs),
            "other_acquisition": str(a.other),
            "total_acquisition_cost": str(a.total),
            "sale_price": str(s.sale_price),
            "selling_fee": str(s.selling_fee),
            "outbound_shipping": str(s.outbound_shipping),
            "packaging": str(s.packaging),
            "expected_refunds": str(s.expected_refunds),
            "other_selling": str(s.other),
            "selling_costs": str(s.total),
            "net_proceeds": str(self.net_proceeds),
            "net_profit": str(self.net_profit),
            "roi": str(self.roi) if self.roi is not None else "n/a",
        }


def acquisition_costs(price: Decimal, channel: PurchaseChannel, extras: Extras) -> AcquisitionCosts:
    shipping = (
        extras.inbound_shipping
        if extras.inbound_shipping is not None
        else channel.default_inbound_shipping
    )
    return AcquisitionCosts(
        purchase_price=price,
        buyer_fee=compute_fee(channel.buyer_fee, price),
        inbound_shipping=shipping,
        cleaning=extras.cleaning,
        repairs=extras.repairs,
        other=extras.other,
    )


def selling_costs(sale_price: Decimal, channel: SellingChannel) -> SellingCosts:
    return SellingCosts(
        sale_price=sale_price,
        selling_fee=compute_fee(channel.selling_fee, sale_price),
        outbound_shipping=channel.outbound_shipping_paid_by_seller,
        packaging=channel.packaging_cost,
        expected_refunds=round_money(sale_price * channel.expected_refund_rate),
        other=channel.other_selling_costs,
    )


def default_extras(fees: FeesConfig) -> Extras:
    return Extras(
        cleaning=fees.default_cleaning_cost,
        repairs=fees.default_repair_cost,
        other=fees.default_other_acquisition_cost,
    )


def profit_breakdown(
    purchase_price: Decimal,
    sale_price: Decimal,
    fees: FeesConfig,
    *,
    extras: Extras | None = None,
    purchase_channel: str | None = None,
    selling_channel: str | None = None,
) -> ProfitBreakdown:
    buy = fees.purchase_channels[purchase_channel or fees.default_purchase_channel]
    sell = fees.selling_channels[selling_channel or fees.default_selling_channel]
    return ProfitBreakdown(
        acquisition=acquisition_costs(purchase_price, buy, extras or default_extras(fees)),
        selling=selling_costs(sale_price, sell),
        currency=fees.currency,
    )
