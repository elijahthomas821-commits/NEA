"""Inputs and outputs of the identification step."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.normalisation.size import UNKNOWN as UNKNOWN_SIZE
from app.analysis.normalisation.size import SizeResult
from app.core.enums import Condition, IdentificationMethod

BrandSource = Literal[
    "field", "notes", "title", "description", "fuzzy", "ai", "mislabel_ai", "manual"
]  # fmt: skip
CategorySource = Literal["field", "notes", "title", "description", "product", "ai", "manual"]


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class BrandEntry(Frozen):
    id: int
    slug: str
    name: str
    aliases: list[str]  # normalised
    negative_aliases: list[str] = Field(default_factory=list)  # normalised
    base_risk: Decimal = Decimal("0.3")


class CategoryEntry(Frozen):
    id: int
    slug: str
    name: str
    parent_id: int | None = None
    in_scope: bool = False
    priority: int = 0
    keywords: list[str] = Field(default_factory=list)  # normalised


class Catalogue(Frozen):
    brands: list[BrandEntry]
    categories: list[CategoryEntry]

    def brand_by_slug(self, slug: str | None) -> BrandEntry | None:
        return next((b for b in self.brands if b.slug == slug), None)

    def brand_by_id(self, brand_id: int | None) -> BrandEntry | None:
        return next((b for b in self.brands if b.id == brand_id), None)

    def category_by_slug(self, slug: str | None) -> CategoryEntry | None:
        return next((c for c in self.categories if c.slug == slug), None)

    def category_by_id(self, category_id: int | None) -> CategoryEntry | None:
        return next((c for c in self.categories if c.id == category_id), None)


class ListingText(Frozen):
    """What identification reads from a listing."""

    title: str
    description: str | None = None
    raw_brand: str | None = None
    raw_category: str | None = None
    raw_size: str | None = None
    raw_colour: str | None = None
    raw_condition: str | None = None
    operator_notes: str | None = None


class Contradiction(Frozen):
    code: str
    detail: str


class IdentificationResult(Frozen):
    brand_id: int | None = None
    brand_slug: str | None = None
    brand_confidence: Decimal = Decimal(0)
    brand_source: BrandSource | None = None
    brand_field_generic: bool = False  # the seller chose "Other"/"Unbranded"
    unknown_brand: str | None = None  # a brand given that is not in the catalogue
    category_id: int | None = None
    category_slug: str | None = None
    category_in_scope: bool | None = None
    category_confidence: Decimal = Decimal(0)
    category_source: CategorySource | None = None
    size: SizeResult = UNKNOWN_SIZE
    colour: str | None = None
    condition: Condition | None = None
    condition_source: str | None = None
    damage_terms: list[str] = Field(default_factory=list)
    replica_terms: list[str] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    tokens: list[str] = Field(default_factory=list)  # normalised title + notes
    model_tokens: list[str] = Field(default_factory=list)  # tokens left for product matching
    method: IdentificationMethod = IdentificationMethod.RULES
    mislabel: bool = False

    @property
    def confidence(self) -> Decimal:
        """Overall identification confidence: the weaker of brand and category."""
        return min(self.brand_confidence, self.category_confidence)

    @property
    def has_contradictions(self) -> bool:
        return bool(self.contradictions)
