"""Purchases, inventory, resales and prediction outcomes."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import CompLevel, Condition, InventoryStatus
from app.models.base import (
    Base,
    Money,
    Ratio,
    created_at,
    currency_check,
    enum_check,
    non_negative,
    pk,
    updated_at,
)


class Purchase(Base):
    """What you actually paid. Recorded by you after buying on the marketplace yourself."""

    __tablename__ = "purchases"
    __table_args__ = (
        CheckConstraint(
            "total_acquisition_cost = purchase_price + buyer_protection_fee"
            " + inbound_shipping + other_acquisition_costs",
            name="total_is_sum",
        ),
        non_negative("purchase_price"),
        non_negative("buyer_protection_fee"),
        non_negative("inbound_shipping"),
        non_negative("other_acquisition_costs"),
        CheckConstraint("item_count >= 1", name="item_count_positive"),
        currency_check(),
    )

    id: Mapped[int] = pk()
    listing_id: Mapped[int | None] = mapped_column(
        ForeignKey("listings.id", ondelete="SET NULL"), index=True
    )
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))
    evaluation_id: Mapped[int | None] = mapped_column(
        ForeignKey("listing_evaluations.id", ondelete="SET NULL")
    )
    marketplace: Mapped[str] = mapped_column(ForeignKey("marketplaces.code"))
    seller_id: Mapped[int | None] = mapped_column(ForeignKey("sellers.id", ondelete="SET NULL"))
    purchased_at: Mapped[datetime] = mapped_column()
    currency: Mapped[str] = mapped_column(String(3))
    purchase_price: Mapped[Decimal] = mapped_column(Money)
    buyer_protection_fee: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    inbound_shipping: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    other_acquisition_costs: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    total_acquisition_cost: Mapped[Decimal] = mapped_column(Money)
    item_count: Mapped[int] = mapped_column(Integer, server_default=text("1"))
    notes: Mapped[str | None] = mapped_column(Text)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    items: Mapped[list[InventoryItem]] = relationship(back_populates="purchase")


class InventoryItem(Base):
    __tablename__ = "inventory_items"
    __table_args__ = (
        enum_check("status", InventoryStatus),
        enum_check("condition_on_receipt", Condition, nullable=True),
        non_negative("allocated_acquisition_cost"),
        non_negative("cleaning_cost"),
        non_negative("repair_cost"),
        non_negative("other_costs"),
        non_negative("listed_price"),
        currency_check(),
        Index("ix_inventory_items_brand_category", "brand_id", "category_id"),
    )

    id: Mapped[int] = pk()
    purchase_id: Mapped[int] = mapped_column(
        ForeignKey("purchases.id", ondelete="RESTRICT"), index=True
    )
    listing_id: Mapped[int | None] = mapped_column(ForeignKey("listings.id", ondelete="SET NULL"))
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id", ondelete="SET NULL"))
    brand_id: Mapped[int | None] = mapped_column(ForeignKey("brands.id", ondelete="SET NULL"))
    category_id: Mapped[int | None] = mapped_column(
        ForeignKey("categories.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300))
    size_normalised: Mapped[str | None] = mapped_column(String(10))
    colour: Mapped[str | None] = mapped_column(String(30))
    condition_on_receipt: Mapped[str | None] = mapped_column(String(20))
    currency: Mapped[str] = mapped_column(String(3))
    # Share of the purchase total (bundles are split across items).
    allocated_acquisition_cost: Mapped[Decimal] = mapped_column(Money)
    cleaning_cost: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    repair_cost: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    other_costs: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    # Snapshot of the prediction at purchase time.
    expected_resale_price: Mapped[Decimal | None] = mapped_column(Money)
    expected_profit: Mapped[Decimal | None] = mapped_column(Money)
    status: Mapped[str] = mapped_column(String(20), server_default=text("'ordered'"), index=True)
    received_at: Mapped[datetime | None] = mapped_column()
    listed_at: Mapped[datetime | None] = mapped_column()
    listed_price: Mapped[Decimal | None] = mapped_column(Money)
    listing_channel: Mapped[str | None] = mapped_column(String(32))
    listing_url: Mapped[str | None] = mapped_column(String(500))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    purchase: Mapped[Purchase] = relationship(back_populates="items")
    resale: Mapped[Resale | None] = relationship(back_populates="item", uselist=False)

    @property
    def total_cost_basis(self) -> Decimal:
        return (
            self.allocated_acquisition_cost
            + self.cleaning_cost
            + self.repair_cost
            + self.other_costs
        )


class InventoryEvent(Base):
    __tablename__ = "inventory_events"
    __table_args__ = (
        enum_check("to_status", InventoryStatus),
        enum_check("from_status", InventoryStatus, nullable=True),
    )

    id: Mapped[int] = pk()
    inventory_item_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_items.id", ondelete="CASCADE"), index=True
    )
    from_status: Mapped[str | None] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20))
    occurred_at: Mapped[datetime] = mapped_column()
    note: Mapped[str | None] = mapped_column(String(500))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Resale(Base):
    __tablename__ = "resales"
    __table_args__ = (
        CheckConstraint(
            "net_proceeds = sale_price + shipping_charged_to_buyer - selling_fees"
            " - outbound_shipping_cost - refunds - other_selling_costs",
            name="net_is_sum",
        ),
        CheckConstraint("sale_price > 0", name="sale_price_positive"),
        non_negative("selling_fees"),
        non_negative("outbound_shipping_cost"),
        non_negative("shipping_charged_to_buyer"),
        non_negative("refunds"),
        non_negative("other_selling_costs"),
        currency_check(),
    )

    id: Mapped[int] = pk()
    inventory_item_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_items.id", ondelete="CASCADE"), unique=True
    )
    channel: Mapped[str] = mapped_column(String(32))
    sold_at: Mapped[datetime] = mapped_column()
    currency: Mapped[str] = mapped_column(String(3))
    sale_price: Mapped[Decimal] = mapped_column(Money)
    selling_fees: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    outbound_shipping_cost: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    shipping_charged_to_buyer: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    refunds: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    other_selling_costs: Mapped[Decimal] = mapped_column(Money, server_default=text("0"))
    net_proceeds: Mapped[Decimal] = mapped_column(Money)
    paid_out_at: Mapped[datetime | None] = mapped_column()
    market_sale_id: Mapped[int | None] = mapped_column(
        ForeignKey("market_sales.id", ondelete="SET NULL")
    )
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    item: Mapped[InventoryItem] = relationship(back_populates="resale")


class PredictionResult(Base):
    """What the system predicted at purchase time vs what actually happened."""

    __tablename__ = "prediction_results"
    __table_args__ = (enum_check("predicted_comp_level", CompLevel, nullable=True),)

    id: Mapped[int] = pk()
    inventory_item_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_items.id", ondelete="CASCADE"), unique=True
    )
    evaluation_id: Mapped[int | None] = mapped_column(
        ForeignKey("listing_evaluations.id", ondelete="SET NULL")
    )
    model_version: Mapped[str] = mapped_column(String(20))
    currency: Mapped[str] = mapped_column(String(3))
    predicted_quick_sale: Mapped[Decimal | None] = mapped_column(Money)
    predicted_expected_sale: Mapped[Decimal | None] = mapped_column(Money)
    predicted_optimistic_sale: Mapped[Decimal | None] = mapped_column(Money)
    predicted_profit: Mapped[Decimal | None] = mapped_column(Money)
    predicted_roi: Mapped[Decimal | None] = mapped_column(Ratio)
    predicted_days_to_sale: Mapped[Decimal | None] = mapped_column(Numeric(8, 1))
    predicted_comp_sample_size: Mapped[int | None] = mapped_column(Integer)
    predicted_comp_level: Mapped[str | None] = mapped_column(String(8))
    predicted_from_price_guide: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    actual_sale_price: Mapped[Decimal | None] = mapped_column(Money)
    actual_profit: Mapped[Decimal | None] = mapped_column(Money)
    actual_roi: Mapped[Decimal | None] = mapped_column(Ratio)
    actual_days_to_sale: Mapped[int | None] = mapped_column(Integer)
    price_error: Mapped[Decimal | None] = mapped_column(Money)
    price_error_pct: Mapped[Decimal | None] = mapped_column(Ratio)
    actual_within_quick_optimistic: Mapped[bool | None] = mapped_column(Boolean)
    resolved_at: Mapped[datetime | None] = mapped_column()
    created_at: Mapped[datetime] = created_at()
