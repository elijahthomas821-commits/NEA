"""Reference data and the product catalogue."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AliasSource, AliasType, ConfigKind, ProductLevel
from app.models.base import (
    Base,
    Money,
    Score,
    created_at,
    currency_check,
    enum_check,
    pk,
    score_check,
    updated_at,
)


class Marketplace(Base):
    __tablename__ = "marketplaces"

    code: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    base_url: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = created_at()


class Brand(Base):
    __tablename__ = "brands"
    __table_args__ = (score_check("base_authenticity_risk"),)

    id: Mapped[int] = pk()
    name: Mapped[str] = mapped_column(String(100), unique=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    base_authenticity_risk: Mapped[Decimal] = mapped_column(Score, server_default=text("0.3"))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    aliases: Mapped[list[BrandAlias]] = relationship(
        back_populates="brand", cascade="all, delete-orphan", passive_deletes=True
    )


class BrandAlias(Base):
    __tablename__ = "brand_aliases"
    __table_args__ = (UniqueConstraint("brand_id", "alias_normalised"),)

    id: Mapped[int] = pk()
    brand_id: Mapped[int] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    alias: Mapped[str] = mapped_column(String(100))
    alias_normalised: Mapped[str] = mapped_column(String(100), index=True)
    # True for wording that mentions the brand but means "not this brand" ("... style").
    is_negative: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    created_at: Mapped[datetime] = created_at()

    brand: Mapped[Brand] = relationship(back_populates="aliases")


class Category(Base):
    __tablename__ = "categories"

    id: Mapped[int] = pk()
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("categories.id", ondelete="RESTRICT"), index=True
    )
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(100))
    level: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    in_scope: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    # Tie-breaker when keywords of several categories match with equal specificity.
    priority: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    aliases: Mapped[list[CategoryAlias]] = relationship(
        back_populates="category", cascade="all, delete-orphan", passive_deletes=True
    )


class CategoryAlias(Base):
    __tablename__ = "category_aliases"

    id: Mapped[int] = pk()
    category_id: Mapped[int] = mapped_column(
        ForeignKey("categories.id", ondelete="CASCADE"), index=True
    )
    alias: Mapped[str] = mapped_column(String(100))
    # Globally unique: one keyword must point to exactly one category.
    alias_normalised: Mapped[str] = mapped_column(String(100), unique=True)
    created_at: Mapped[datetime] = created_at()

    category: Mapped[Category] = relationship(back_populates="aliases")


class Product(Base):
    __tablename__ = "products"
    __table_args__ = (
        UniqueConstraint("brand_id", "slug"),
        enum_check("level", ProductLevel),
        currency_check("retail_currency"),
        CheckConstraint(
            "reference_retail_price IS NULL OR retail_currency IS NOT NULL",
            name="retail_price_has_currency",
        ),
        Index(
            "uq_products_brand_model_code",
            "brand_id",
            "model_code",
            unique=True,
            postgresql_where=text("model_code IS NOT NULL"),
        ),
        Index(
            "uq_products_generic_per_brand_category",
            "brand_id",
            "category_id",
            unique=True,
            postgresql_where=text("level = 'brand_category_generic'"),
        ),
        Index("ix_products_brand_category", "brand_id", "category_id"),
    )

    id: Mapped[int] = pk()
    brand_id: Mapped[int] = mapped_column(ForeignKey("brands.id", ondelete="RESTRICT"))
    category_id: Mapped[int] = mapped_column(
        ForeignKey("categories.id", ondelete="RESTRICT"), index=True
    )
    level: Mapped[str] = mapped_column(String(32))
    canonical_name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(200))
    model_code: Mapped[str | None] = mapped_column(String(50))
    gender: Mapped[str | None] = mapped_column(String(10))
    season: Mapped[str | None] = mapped_column(String(20))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    reference_retail_price: Mapped[Decimal | None] = mapped_column(Money)
    retail_currency: Mapped[str | None] = mapped_column(String(3))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    brand: Mapped[Brand] = relationship()
    category: Mapped[Category] = relationship()
    aliases: Mapped[list[ProductAlias]] = relationship(
        back_populates="product", cascade="all, delete-orphan", passive_deletes=True
    )


class ProductAlias(Base):
    __tablename__ = "product_aliases"
    __table_args__ = (
        UniqueConstraint("product_id", "alias_normalised"),
        enum_check("alias_type", AliasType),
        enum_check("source", AliasSource),
        score_check("weight"),
    )

    id: Mapped[int] = pk()
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), index=True
    )
    alias: Mapped[str] = mapped_column(String(200))
    alias_normalised: Mapped[str] = mapped_column(String(200), index=True)
    alias_type: Mapped[str] = mapped_column(String(20), server_default=text("'name'"))
    weight: Mapped[Decimal] = mapped_column(Score, server_default=text("1"))
    source: Mapped[str] = mapped_column(String(20), server_default=text("'seed'"))
    created_at: Mapped[datetime] = created_at()

    product: Mapped[Product] = relationship(back_populates="aliases")


class FxRate(Base):
    __tablename__ = "fx_rates"
    __table_args__ = (
        UniqueConstraint("base", "quote", "as_of"),
        CheckConstraint("rate > 0", name="rate_positive"),
        currency_check("base"),
        currency_check("quote"),
    )

    id: Mapped[int] = pk()
    base: Mapped[str] = mapped_column(String(3))
    quote: Mapped[str] = mapped_column(String(3))
    # 1 unit of base = rate units of quote.
    rate: Mapped[Decimal] = mapped_column(Numeric(18, 8))
    as_of: Mapped[date] = mapped_column(Date)
    source: Mapped[str] = mapped_column(String(50), server_default=text("'manual'"))
    created_at: Mapped[datetime] = created_at()


class ConfigVersion(Base):
    __tablename__ = "config_versions"
    __table_args__ = (
        UniqueConstraint("kind", "name", "version"),
        enum_check("kind", ConfigKind),
        CheckConstraint("version >= 1", name="version_positive"),
        Index(
            "uq_config_versions_one_active",
            "kind",
            "name",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )

    id: Mapped[int] = pk()
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(64), server_default=text("'default'"))
    version: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    checksum: Mapped[str] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()
    created_by: Mapped[str | None] = mapped_column(String(100))


class BotState(Base):
    """Small durable key/value store for the Telegram bot (poll offset, conversations)."""

    __tablename__ = "bot_state"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB)
    expires_at: Mapped[datetime | None] = mapped_column(index=True)
    updated_at: Mapped[datetime] = updated_at()


class TaskFailure(Base):
    """Dead-letter record for background tasks that exhausted their retries."""

    __tablename__ = "task_failures"

    id: Mapped[int] = pk()
    task_name: Mapped[str] = mapped_column(String(200))
    task_id: Mapped[str | None] = mapped_column(String(100))
    args: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    error: Mapped[str] = mapped_column(String(1000))
    retries: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    failed_at: Mapped[datetime] = created_at()
    resolved_at: Mapped[datetime | None] = mapped_column()
