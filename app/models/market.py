"""Market data: completed sales (comps) and precomputed statistics."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import CompLevel, Condition, PriceType, SaleSource
from app.models.base import (
    Base,
    Money,
    Score,
    created_at,
    currency_check,
    enum_check,
    non_negative,
    pk,
    score_check,
    updated_at,
)


class MarketSale(Base):
    """A completed sale used as a comparable. Never an asking price of an unsold listing."""

    __tablename__ = "market_sales"
    __table_args__ = (
        UniqueConstraint("source", "source_ref"),
        enum_check("source", SaleSource),
        enum_check("price_type", PriceType),
        enum_check("condition", Condition, nullable=True),
        CheckConstraint("sale_price > 0", name="sale_price_positive"),
        CheckConstraint("listed_at IS NULL OR listed_at <= sold_at", name="listed_before_sold"),
        non_negative("days_to_sale"),
        currency_check(),
        score_check("trust_weight"),
        score_check("match_confidence"),
        Index("ix_market_sales_product_sold", "product_id", text("sold_at DESC")),
        Index(
            "ix_market_sales_brand_category_sold", "brand_id", "category_id", text("sold_at DESC")
        ),
        Index(
            "ix_market_sales_product_size_condition", "product_id", "size_normalised", "condition"
        ),
    )

    id: Mapped[int] = pk()
    source: Mapped[str] = mapped_column(String(32))
    source_ref: Mapped[str | None] = mapped_column(String(200))
    marketplace: Mapped[str | None] = mapped_column(ForeignKey("marketplaces.code"))
    listing_id: Mapped[int | None] = mapped_column(ForeignKey("listings.id", ondelete="SET NULL"))
    inventory_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventory_items.id", ondelete="SET NULL")
    )
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id", ondelete="SET NULL"))
    brand_id: Mapped[int] = mapped_column(ForeignKey("brands.id", ondelete="RESTRICT"))
    category_id: Mapped[int] = mapped_column(
        ForeignKey("categories.id", ondelete="RESTRICT"), index=True
    )
    title: Mapped[str | None] = mapped_column(String(300))
    size_normalised: Mapped[str | None] = mapped_column(String(10))
    colour: Mapped[str | None] = mapped_column(String(30))
    condition: Mapped[str | None] = mapped_column(String(20))
    sale_price: Mapped[Decimal] = mapped_column(Money)
    currency: Mapped[str] = mapped_column(String(3))
    price_type: Mapped[str] = mapped_column(String(32))
    listed_at: Mapped[datetime | None] = mapped_column()
    sold_at: Mapped[datetime] = mapped_column()
    # Whole UTC days from listing to sale; set by the service when listed_at is known.
    days_to_sale: Mapped[int | None] = mapped_column(Integer)
    trust_weight: Mapped[Decimal] = mapped_column(Score, server_default=text("1"))
    match_confidence: Mapped[Decimal] = mapped_column(Score, server_default=text("1"))
    is_outlier: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    excluded: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    excluded_reason: Mapped[str | None] = mapped_column(String(200))
    notes: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class MarketStatistic(Base):
    """Nightly snapshot of market statistics per scope (for reporting; pricing recomputes)."""

    __tablename__ = "market_statistics"
    __table_args__ = (
        Index(
            "uq_market_statistics_scope",
            "scope_level",
            "product_id",
            "brand_id",
            "category_id",
            "size_normalised",
            "condition",
            "window_days",
            "currency",
            unique=True,
            postgresql_nulls_not_distinct=True,
        ),
        enum_check("scope_level", CompLevel),
        currency_check(),
    )

    id: Mapped[int] = pk()
    scope_level: Mapped[str] = mapped_column(String(8))
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"))
    brand_id: Mapped[int | None] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"))
    category_id: Mapped[int | None] = mapped_column(ForeignKey("categories.id", ondelete="CASCADE"))
    size_normalised: Mapped[str | None] = mapped_column(String(10))
    condition: Mapped[str | None] = mapped_column(String(20))
    window_days: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3))
    sample_size: Mapped[int] = mapped_column(Integer)
    effective_sample_size: Mapped[Decimal] = mapped_column(Numeric(10, 2))
    p10: Mapped[Decimal | None] = mapped_column(Money)
    p25: Mapped[Decimal | None] = mapped_column(Money)
    median: Mapped[Decimal | None] = mapped_column(Money)
    p75: Mapped[Decimal | None] = mapped_column(Money)
    p90: Mapped[Decimal | None] = mapped_column(Money)
    median_days_to_sale: Mapped[Decimal | None] = mapped_column(Numeric(8, 1))
    sales_last_30d: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    sales_last_90d: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    active_listings_observed: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    method_version: Mapped[str] = mapped_column(String(20))
    computed_at: Mapped[datetime] = mapped_column()
