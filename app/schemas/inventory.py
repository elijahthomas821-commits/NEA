"""Purchases, inventory, sales and alerts API schemas."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.enums import InventoryStatus, UserDecision
from app.core.money import normalise_currency

Money = Annotated[Decimal, Field(ge=0, max_digits=12, decimal_places=2)]
PositiveMoney = Annotated[Decimal, Field(gt=0, max_digits=12, decimal_places=2)]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PurchaseItemIn(_In):
    listing_id: int | None = Field(default=None, description="a listing you sent in")
    evaluation_id: int | None = Field(
        default=None, description="defaults to the listing's latest evaluation"
    )
    title: str | None = Field(
        default=None, max_length=300, description="required without a listing"
    )
    brand: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=100)
    size: str | None = Field(default=None, max_length=50)
    colour: str | None = Field(default=None, max_length=50)
    expected_resale_price: PositiveMoney | None = None
    allocated_cost: Money | None = Field(default=None, description='"manual" allocation only')

    @model_validator(mode="after")
    def _needs_something(self) -> PurchaseItemIn:
        if self.listing_id is None and not self.title:
            raise ValueError("give a listing_id or a title")
        return self


class PurchaseIn(_In):
    """What you actually paid, after buying on the marketplace yourself."""

    purchase_price: PositiveMoney = Field(description="the item price(s) you paid, before fees")
    buyer_protection_fee: Money | None = Field(
        default=None, description="defaults to your fee settings"
    )
    inbound_shipping: Money | None = Field(
        default=None, description="defaults to your fee settings"
    )
    other_acquisition_costs: Money = Decimal(0)
    currency: str | None = None
    marketplace: str = Field(default="vinted", max_length=32)
    purchased_at: datetime | None = None
    allocation: Literal["expected_value", "equal", "manual"] = "expected_value"
    alert_id: int | None = None
    items: list[PurchaseItemIn] = Field(min_length=1, max_length=50)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str | None) -> str | None:
        return normalise_currency(value) if value else None


class InventoryItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    purchase_id: int
    listing_id: int | None
    product_id: int | None
    brand_id: int | None
    category_id: int | None
    title: str
    size_normalised: str | None
    colour: str | None
    condition_on_receipt: str | None
    status: str
    currency: str
    allocated_acquisition_cost: Decimal
    cleaning_cost: Decimal
    repair_cost: Decimal
    other_costs: Decimal
    total_cost_basis: Decimal
    expected_resale_price: Decimal | None
    expected_profit: Decimal | None
    received_at: datetime | None
    listed_at: datetime | None
    listed_price: Decimal | None
    listing_channel: str | None
    listing_url: str | None
    notes: str | None


class PurchaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    marketplace: str
    purchased_at: datetime
    currency: str
    purchase_price: Decimal
    buyer_protection_fee: Decimal
    inbound_shipping: Decimal
    other_acquisition_costs: Decimal
    total_acquisition_cost: Decimal
    item_count: int
    alert_id: int | None
    notes: str | None
    items: list[InventoryItemOut]


class TransitionIn(_In):
    status: InventoryStatus
    at: datetime | None = None
    note: str | None = Field(default=None, max_length=500)
    listed_price: PositiveMoney | None = None
    listing_channel: str | None = Field(default=None, max_length=32)
    listing_url: str | None = Field(default=None, max_length=500)
    condition: str | None = Field(default=None, max_length=50, description="when received")


class ItemUpdate(_In):
    cleaning_cost: Money | None = None
    repair_cost: Money | None = None
    other_costs: Money | None = None
    listed_price: PositiveMoney | None = None
    listing_url: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=2000)


class ResaleIn(_In):
    """You sold the item. Costs you leave out default to your fee settings for the channel."""

    sale_price: PositiveMoney
    sold_at: datetime | None = None
    channel: str | None = Field(default=None, max_length=32)
    currency: str | None = None
    selling_fees: Money | None = None
    outbound_shipping_cost: Money | None = None
    shipping_charged_to_buyer: Money = Decimal(0)
    refunds: Money = Decimal(0)
    other_selling_costs: Money | None = None
    notes: str | None = Field(default=None, max_length=2000)


class ResaleUpdate(_In):
    sale_price: PositiveMoney | None = None
    sold_at: datetime | None = None
    selling_fees: Money | None = None
    outbound_shipping_cost: Money | None = None
    shipping_charged_to_buyer: Money | None = None
    refunds: Money | None = None
    other_selling_costs: Money | None = None
    paid_out_at: datetime | None = None
    notes: str | None = Field(default=None, max_length=2000)


class CancelIn(_In):
    reason: str | None = Field(default=None, max_length=300)


class ResaleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    inventory_item_id: int
    channel: str
    sold_at: datetime
    currency: str
    sale_price: Decimal
    shipping_charged_to_buyer: Decimal
    selling_fees: Decimal
    outbound_shipping_cost: Decimal
    refunds: Decimal
    other_selling_costs: Decimal
    net_proceeds: Decimal
    paid_out_at: datetime | None
    market_sale_id: int | None
    notes: str | None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    from_status: str | None
    to_status: str
    occurred_at: datetime
    note: str | None


class PredictionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evaluation_id: int | None
    model_version: str
    predicted_quick_sale: Decimal | None
    predicted_expected_sale: Decimal | None
    predicted_optimistic_sale: Decimal | None
    predicted_profit: Decimal | None
    predicted_roi: Decimal | None
    predicted_days_to_sale: Decimal | None
    predicted_comp_level: str | None
    predicted_from_price_guide: bool
    actual_sale_price: Decimal | None
    actual_profit: Decimal | None
    actual_roi: Decimal | None
    actual_days_to_sale: int | None
    price_error: Decimal | None
    price_error_pct: Decimal | None
    actual_within_quick_optimistic: bool | None
    resolved_at: datetime | None


class InventoryDetailOut(BaseModel):
    item: InventoryItemOut
    purchased_at: datetime
    days_held: int
    events: list[EventOut]
    sale: ResaleOut | None
    profit: Decimal | None
    prediction: PredictionOut | None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evaluation_id: int
    listing_id: int
    priority: str
    status: str
    attempts: int
    last_error: str | None
    sent_at: datetime | None
    user_decision: str | None
    decided_at: datetime | None
    decision_note: str | None
    created_at: datetime


class DecisionIn(_In):
    decision: UserDecision
    note: str | None = Field(default=None, max_length=1000)
