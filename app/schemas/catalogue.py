"""Catalogue API schemas."""

from __future__ import annotations

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import AliasType, ProductLevel


class BrandIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=100)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    negative_aliases: list[str] = Field(default_factory=list, max_length=50)
    base_authenticity_risk: Decimal = Field(default=Decimal("0.3"), ge=0, le=1)


class AliasIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alias: str = Field(min_length=1, max_length=100)
    is_negative: bool = False


class ProductIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    brand_id: int
    category_id: int
    name: str = Field(min_length=1, max_length=200)
    level: ProductLevel = ProductLevel.PRODUCT_LINE
    model_code: str | None = Field(default=None, max_length=50)
    aliases: list[str] = Field(default_factory=list, max_length=50)


class ProductAliasIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alias: str = Field(min_length=1, max_length=200)
    weight: Decimal = Field(default=Decimal(1), gt=0, le=1)
    alias_type: AliasType = AliasType.NAME


class KeywordIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    keyword: str = Field(min_length=1, max_length=100)


class BrandOut(BaseModel):
    id: int
    name: str
    slug: str
    base_authenticity_risk: Decimal
    is_active: bool
    aliases: list[str] = Field(default_factory=list)
    negative_aliases: list[str] = Field(default_factory=list)


class CategoryOut(BaseModel):
    id: int
    slug: str
    name: str
    parent_id: int | None
    in_scope: bool
    keywords: list[str]


class ProductOut(BaseModel):
    id: int
    brand_id: int
    category_id: int
    level: str
    name: str
    model_code: str | None
    aliases: list[str]


class IdentifyIn(BaseModel):
    """Preview how a listing would be identified (rules only; nothing is stored)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    brand: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=100)
    size: str | None = Field(default=None, max_length=50)
    colour: str | None = Field(default=None, max_length=50)
    condition: str | None = Field(default=None, max_length=50)
    notes: str | None = Field(default=None, max_length=1000)
