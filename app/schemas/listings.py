"""Listing API schemas."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.collectors.base import RawSeller
from app.core.enums import ListingStatus
from app.core.money import normalise_currency


class ListingSubmission(BaseModel):
    """A listing you found and want evaluated. Only title is strictly required."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    marketplace: str = Field(default="vinted", max_length=32)
    url: HttpUrl | None = None
    external_id: str | None = Field(default=None, max_length=100)
    title: str | None = Field(default=None, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    brand: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=100)
    size: str | None = Field(default=None, max_length=50)
    colour: str | None = Field(default=None, max_length=50)
    condition: str | None = Field(default=None, max_length=50)
    price: Decimal | None = Field(default=None, gt=0, max_digits=12, decimal_places=2)
    currency: str | None = None
    listed_at: datetime | None = None
    seller: RawSeller | None = None
    notes: str | None = Field(default=None, max_length=1000)
    notify: bool = True

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str | None) -> str | None:
        return normalise_currency(value) if value else None


class QuickSubmission(BaseModel):
    """Free text such as ``"https://www.vinted.co.uk/items/123-stone-island-hoodie £45 L"``."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=3, max_length=2000)
    notify: bool = True


class ListingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    price: Decimal | None = Field(default=None, gt=0, max_digits=12, decimal_places=2)
    currency: str | None = None
    status: ListingStatus | None = None
    note: str | None = Field(default=None, max_length=300)
    reevaluate: bool = True

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str | None) -> str | None:
        return normalise_currency(value) if value else None


class ListingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    marketplace: str
    external_id: str
    url: str | None
    source: str
    title: str
    description: str | None
    raw_brand: str | None
    raw_category: str | None
    raw_size: str | None
    raw_colour: str | None
    raw_condition: str | None
    brand_id: int | None
    category_id: int | None
    matched_product_id: int | None
    match_confidence: Decimal | None
    size_normalised: str | None
    colour: str | None
    condition: str | None
    price: Decimal | None
    currency: str | None
    status: str
    listed_at: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    possible_duplicate_of: int | None
    seller_id: int | None


class ListingIngestOut(BaseModel):
    listing: ListingOut
    created: bool
    evaluation_queued: bool
    missing_fields: list[str] = Field(default_factory=list)


class ImageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    position: int
    sha256: str | None
    phash: str | None
    width: int | None
    height: int | None
    content_type: str | None
    created: bool = False


class IngestionRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    source: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    rows_total: int
    rows_created: int
    rows_updated: int
    rows_skipped: int
    rows_failed: int
    error_summary: str | None
    report: dict[str, object]


class Page(BaseModel):
    total: int
    limit: int
    offset: int
