"""Marketplace data: sellers, listings, photos, price and status history, import runs."""

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

from app.core.enums import Condition, IdentificationMethod, ListingStatus
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
    values_check,
)

SELLER_FLAGS = ["none", "trusted", "blocked"]
LISTING_SOURCES = ["telegram", "api", "csv", "fixture"]
IMAGE_SOURCES = ["upload", "telegram"]
RUN_KINDS = ["listings_csv", "sales_csv", "api_batch", "fixture"]
RUN_STATUSES = ["running", "ok", "partial", "failed"]


class Seller(Base):
    __tablename__ = "sellers"
    __table_args__ = (
        UniqueConstraint("marketplace", "external_seller_id"),
        values_check("operator_flag", SELLER_FLAGS),
        CheckConstraint("rating IS NULL OR (rating >= 0 AND rating <= 5)", name="rating_range"),
        non_negative("review_count"),
    )

    id: Mapped[int] = pk()
    marketplace: Mapped[str] = mapped_column(ForeignKey("marketplaces.code"))
    external_seller_id: Mapped[str] = mapped_column(String(100))
    username: Mapped[str | None] = mapped_column(String(100))
    rating: Mapped[Decimal | None] = mapped_column(Numeric(3, 2))
    review_count: Mapped[int | None] = mapped_column(Integer)
    country: Mapped[str | None] = mapped_column(String(2))
    member_since: Mapped[date | None] = mapped_column(Date)
    operator_flag: Mapped[str] = mapped_column(String(10), server_default=text("'none'"))
    notes: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column()
    last_seen_at: Mapped[datetime] = mapped_column()
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class Listing(Base):
    __tablename__ = "listings"
    __table_args__ = (
        # Primary duplicate guard: one row per marketplace listing.
        UniqueConstraint("marketplace", "external_id"),
        CheckConstraint("price IS NULL OR currency IS NOT NULL", name="price_has_currency"),
        CheckConstraint("price IS NULL OR price > 0", name="price_positive"),
        currency_check(),
        enum_check("condition", Condition, nullable=True),
        enum_check("status", ListingStatus),
        enum_check("identification_method", IdentificationMethod, nullable=True),
        values_check("source", LISTING_SOURCES),
        score_check("match_confidence"),
        Index("ix_listings_status_first_seen", "status", text("first_seen_at DESC")),
        Index("ix_listings_brand_category", "brand_id", "category_id"),
        Index(
            "ix_listings_active_first_seen",
            text("first_seen_at DESC"),
            postgresql_where=text("status = 'active'"),
        ),
    )

    id: Mapped[int] = pk()
    marketplace: Mapped[str] = mapped_column(ForeignKey("marketplaces.code"))
    external_id: Mapped[str] = mapped_column(String(100))
    url: Mapped[str | None] = mapped_column(String(500))
    seller_id: Mapped[int | None] = mapped_column(
        ForeignKey("sellers.id", ondelete="SET NULL"), index=True
    )
    source: Mapped[str] = mapped_column(String(16))

    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text)
    # As supplied by the marketplace / the person submitting it.
    raw_brand: Mapped[str | None] = mapped_column(String(100))
    raw_category: Mapped[str | None] = mapped_column(String(100))
    raw_size: Mapped[str | None] = mapped_column(String(50))
    raw_colour: Mapped[str | None] = mapped_column(String(50))
    raw_condition: Mapped[str | None] = mapped_column(String(50))

    # Normalised by the identification step.
    brand_id: Mapped[int | None] = mapped_column(ForeignKey("brands.id", ondelete="SET NULL"))
    category_id: Mapped[int | None] = mapped_column(
        ForeignKey("categories.id", ondelete="SET NULL"), index=True
    )
    model_text: Mapped[str | None] = mapped_column(String(200))
    size_normalised: Mapped[str | None] = mapped_column(String(10))
    size_system: Mapped[str | None] = mapped_column(String(20))
    is_kids: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    colour: Mapped[str | None] = mapped_column(String(30))
    condition: Mapped[str | None] = mapped_column(String(20))
    identification_method: Mapped[str | None] = mapped_column(String(20))
    matched_product_id: Mapped[int | None] = mapped_column(
        ForeignKey("products.id", ondelete="SET NULL"), index=True
    )
    match_confidence: Mapped[Decimal | None] = mapped_column(Score)

    price: Mapped[Decimal | None] = mapped_column(Money)
    currency: Mapped[str | None] = mapped_column(String(3))

    listed_at: Mapped[datetime | None] = mapped_column()
    first_seen_at: Mapped[datetime] = mapped_column()
    last_seen_at: Mapped[datetime] = mapped_column()
    status: Mapped[str] = mapped_column(String(16), server_default=text("'active'"))
    status_changed_at: Mapped[datetime | None] = mapped_column()

    content_hash: Mapped[str] = mapped_column(String(64))
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    possible_duplicate_of: Mapped[int | None] = mapped_column(
        ForeignKey("listings.id", ondelete="SET NULL")
    )
    submitted_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    images: Mapped[list[ListingImage]] = relationship(
        back_populates="listing",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ListingImage.position",
    )
    seller: Mapped[Seller | None] = relationship()


class ListingImage(Base):
    __tablename__ = "listing_images"
    __table_args__ = (
        UniqueConstraint("listing_id", "position"),
        UniqueConstraint("listing_id", "sha256"),
        values_check("source", IMAGE_SOURCES),
        CheckConstraint("position >= 0", name="position_non_negative"),
    )

    id: Mapped[int] = pk()
    listing_id: Mapped[int] = mapped_column(
        ForeignKey("listings.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(SmallInteger)
    source: Mapped[str] = mapped_column(String(16))
    # Relative path inside the media directory; photos are only ever uploaded, never fetched.
    storage_key: Mapped[str | None] = mapped_column(String(200))
    telegram_file_id: Mapped[str | None] = mapped_column(String(200))
    telegram_file_unique_id: Mapped[str | None] = mapped_column(String(100))
    sha256: Mapped[str | None] = mapped_column(String(64))
    # 64-bit difference hash as 16 hex characters (near-duplicate photo detection).
    phash: Mapped[str | None] = mapped_column(String(16), index=True)
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(50))
    byte_size: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = created_at()

    listing: Mapped[Listing] = relationship(back_populates="images")


class PriceHistory(Base):
    """One row on first sighting and one on every price change (not every observation)."""

    __tablename__ = "price_history"
    __table_args__ = (
        CheckConstraint("price > 0", name="price_positive"),
        currency_check(),
        Index("ix_price_history_listing_observed", "listing_id", text("observed_at DESC")),
    )

    id: Mapped[int] = pk()
    listing_id: Mapped[int] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"))
    price: Mapped[Decimal] = mapped_column(Money)
    currency: Mapped[str] = mapped_column(String(3))
    previous_price: Mapped[Decimal | None] = mapped_column(Money)
    observed_at: Mapped[datetime] = mapped_column()


class ListingStatusHistory(Base):
    __tablename__ = "listing_status_history"
    __table_args__ = (
        enum_check("to_status", ListingStatus),
        enum_check("from_status", ListingStatus, nullable=True),
    )

    id: Mapped[int] = pk()
    listing_id: Mapped[int] = mapped_column(
        ForeignKey("listings.id", ondelete="CASCADE"), index=True
    )
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16))
    observed_at: Mapped[datetime] = mapped_column()
    note: Mapped[str | None] = mapped_column(String(300))


class IngestionRun(Base):
    """A batch import (CSV of listings or sales) with a row-level validation report."""

    __tablename__ = "ingestion_runs"
    __table_args__ = (
        values_check("kind", RUN_KINDS),
        values_check("status", RUN_STATUSES),
    )

    id: Mapped[int] = pk()
    kind: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(16), server_default=text("'running'"))
    started_at: Mapped[datetime] = mapped_column()
    finished_at: Mapped[datetime | None] = mapped_column()
    rows_total: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    rows_created: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    rows_updated: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    rows_skipped: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    rows_failed: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    error_summary: Mapped[str | None] = mapped_column(String(1000))
    report: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
