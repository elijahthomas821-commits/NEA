"""Adapter protocols, marketplace-neutral DTOs and adapter errors."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.enums import PriceType, SaleSource
from app.core.money import normalise_currency


class DTO(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


# --------------------------------------------------------------------------- listings


class RawSeller(DTO):
    external_seller_id: str = Field(min_length=1, max_length=100)
    username: str | None = Field(default=None, max_length=100)
    rating: Decimal | None = Field(default=None, ge=0, le=5)
    review_count: int | None = Field(default=None, ge=0)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    member_since: date | None = None


class RawListing(DTO):
    """A listing as supplied by a source, before any normalisation."""

    marketplace: str = Field(min_length=1, max_length=32)
    external_id: str = Field(min_length=1, max_length=100)
    url: str | None = Field(default=None, max_length=500)
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    raw_brand: str | None = Field(default=None, max_length=100)
    raw_category: str | None = Field(default=None, max_length=100)
    raw_size: str | None = Field(default=None, max_length=50)
    raw_colour: str | None = Field(default=None, max_length=50)
    raw_condition: str | None = Field(default=None, max_length=50)
    price: Decimal | None = Field(default=None, gt=0, max_digits=12, decimal_places=2)
    currency: str | None = None
    listed_at: datetime | None = None
    status: str | None = None
    seller: RawSeller | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "url", "description", "raw_brand", "raw_category", "raw_size", "raw_colour",
        "raw_condition", mode="before",
    )  # fmt: skip
    @classmethod
    def _blank_to_none(cls, value: Any) -> Any:
        return _clean_optional(value) if isinstance(value, str) else value

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str | None) -> str | None:
        return normalise_currency(value) if value else None

    @model_validator(mode="after")
    def _price_currency(self) -> RawListing:
        if self.price is not None and self.currency is None:
            raise ValueError("currency is required when a price is given")
        return self


class ListingQuery(DTO):
    keywords: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    max_price: Decimal | None = None
    limit: int = Field(default=50, ge=1, le=500)


class AdapterPage[T](DTO):
    items: list[T]
    next_cursor: str | None = None


class AdapterCapabilities(DTO):
    supports_search: bool
    supports_item_lookup: bool
    supports_status_refresh: bool
    automated: bool
    max_requests_per_minute: int | None = None
    # Where permission for this access method is documented. Required for automated adapters.
    terms_reference: str


class AdapterHealth(DTO):
    ok: bool
    detail: str = ""


# --------------------------------------------------------------------------- sales


class RawSale(DTO):
    """A completed sale from a market-data source (never an unsold asking price)."""

    source: SaleSource
    source_ref: str | None = Field(default=None, max_length=200)
    marketplace: str | None = Field(default=None, max_length=32)
    title: str | None = Field(default=None, max_length=300)
    brand: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=100)
    product: str | None = Field(default=None, max_length=200)
    size: str | None = Field(default=None, max_length=50)
    colour: str | None = Field(default=None, max_length=50)
    condition: str | None = Field(default=None, max_length=50)
    sale_price: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str
    price_type: PriceType = PriceType.FINAL_SALE_PRICE
    listed_at: datetime | None = None
    sold_at: datetime
    notes: str | None = Field(default=None, max_length=1000)

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str) -> str:
        return normalise_currency(value)

    @model_validator(mode="after")
    def _dates(self) -> RawSale:
        if self.listed_at is not None and self.listed_at > self.sold_at:
            raise ValueError("listed_at must not be after sold_at")
        return self


class SalesQuery(DTO):
    brand: str | None = None
    category: str | None = None
    since: datetime | None = None


# --------------------------------------------------------------------------- protocols


class MarketplaceAdapter(Protocol):
    marketplace: str
    capabilities: AdapterCapabilities

    def search_listings(
        self, query: ListingQuery, since: datetime | None = None
    ) -> AdapterPage[RawListing]: ...

    def get_listing(self, external_id: str) -> RawListing | None: ...

    def health_check(self) -> AdapterHealth: ...


class MarketDataSource(Protocol):
    """Completed sales only — never asking prices of unsold items."""

    source: str
    trust_weight: Decimal

    def fetch_sales(self, query: SalesQuery) -> list[RawSale]: ...


# --------------------------------------------------------------------------- errors


class AdapterError(Exception):
    """Base class for adapter failures."""


class NotSupportedError(AdapterError):
    """The adapter does not offer this operation (e.g. search on a manual source)."""


class AccessDeniedError(AdapterError):
    """401/403/CAPTCHA/challenge. The adapter disables itself; nothing is retried or bypassed."""


class RateLimitedError(AdapterError):
    def __init__(self, retry_after: float, message: str = "rate limited") -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TransientError(AdapterError):
    """Timeouts, 5xx, connection resets: safe to retry with backoff."""


class PayloadInvalidError(AdapterError):
    """The source returned data we cannot parse; the raw payload is quarantined."""

    def __init__(self, message: str, raw: Any = None) -> None:
        super().__init__(message)
        self.raw = raw
