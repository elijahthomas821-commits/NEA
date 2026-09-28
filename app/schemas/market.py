"""Market data API schemas."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import PriceType
from app.core.money import normalise_currency


class SaleIn(BaseModel):
    """A comparable sale you researched (e.g. a sold listing you looked at)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    brand: str = Field(min_length=1, max_length=100, description="slug, name or alias")
    category: str = Field(min_length=1, max_length=100, description="slug, name or keyword")
    product: str | None = Field(default=None, max_length=200, description="product slug or name")
    title: str | None = Field(default=None, max_length=300)
    size: str | None = Field(default=None, max_length=50)
    colour: str | None = Field(default=None, max_length=50)
    condition: str | None = Field(default=None, max_length=50)
    sale_price: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str | None = None
    price_type: PriceType = PriceType.FINAL_SALE_PRICE
    marketplace: str | None = Field(default="vinted", max_length=32)
    listed_at: datetime | None = None
    sold_at: datetime
    source_ref: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=1000)

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str | None) -> str | None:
        return normalise_currency(value) if value else None


class SaleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    excluded: bool
    reason: str | None = Field(default=None, max_length=200)


class EstimateIn(BaseModel):
    """What would this sell for? (a what-if price check; nothing is stored)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    brand: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=100)
    product: str | None = Field(default=None, max_length=200)
    title: str | None = Field(default=None, max_length=300)
    size: str | None = Field(default=None, max_length=50)
    colour: str | None = Field(default=None, max_length=50)
    condition: str | None = Field(default=None, max_length=50)
    currency: str | None = None


class FxRateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base: str
    quote: str
    rate: Decimal = Field(gt=0, max_digits=18, decimal_places=8)
    as_of: date
