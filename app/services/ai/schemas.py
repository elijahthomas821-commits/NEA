"""Strict request/response models for AI listing analysis. No money fields, by design."""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import CheckResult

MAX_LIST_ITEMS = 6
MAX_TEXT = 200


def _trim_list(value: Any) -> Any:
    if isinstance(value, list):
        return [str(v)[:MAX_TEXT] for v in value[:MAX_LIST_ITEMS]]
    return value


class StrictAIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AIChecklistItem(StrictAIModel):
    brand: str = Field(max_length=64)
    code: str = Field(max_length=64)
    result: CheckResult
    note: str = Field(default="", max_length=400)

    @field_validator("note", mode="before")
    @classmethod
    def _trim(cls, value: Any) -> Any:
        return str(value)[:MAX_TEXT] if value is not None else ""


class AIListingAnalysis(StrictAIModel):
    """What the model may tell us. Deliberately contains no price or value fields."""

    brand: str = Field(max_length=64)  # catalogue slug or "unknown"
    category: str = Field(max_length=64)  # catalogue slug or "unknown"
    product_hint: str = Field(default="", max_length=400)
    colour: str = Field(default="unknown", max_length=32)
    identification_confidence: Decimal = Field(ge=0, le=1)
    identification_evidence: list[str] = Field(default_factory=list)
    photo_brand: str = Field(default="unknown", max_length=64)
    photo_brand_confidence: Decimal = Field(default=Decimal(0), ge=0, le=1)
    photo_brand_evidence: list[str] = Field(default_factory=list)
    checklist: list[AIChecklistItem] = Field(default_factory=list)
    photo_quality: Literal["good", "fair", "poor", "none"] = "none"
    concerns: list[str] = Field(default_factory=list)

    @field_validator("identification_evidence", "photo_brand_evidence", "concerns", mode="before")
    @classmethod
    def _limit_lists(cls, value: Any) -> Any:
        return _trim_list(value)

    @field_validator("product_hint", mode="before")
    @classmethod
    def _trim_hint(cls, value: Any) -> Any:
        return str(value)[:MAX_TEXT] if value is not None else ""

    @field_validator("checklist", mode="before")
    @classmethod
    def _limit_checklist(cls, value: Any) -> Any:
        return value[:40] if isinstance(value, list) else value


class AIImage(BaseModel):
    model_config = ConfigDict(frozen=True)

    sha256: str
    media_type: str
    data: bytes = Field(repr=False)


class CatalogueOption(BaseModel):
    model_config = ConfigDict(frozen=True)

    slug: str
    name: str


class ChecklistOption(BaseModel):
    model_config = ConfigDict(frozen=True)

    brand: str
    code: str
    description: str


class AnalysisRequest(BaseModel):
    """Everything sent to the model. Prices are deliberately not included."""

    model_config = ConfigDict(frozen=True)

    title: str
    description: str | None = None
    brand_field: str | None = None
    category_field: str | None = None
    size_field: str | None = None
    condition_field: str | None = None
    operator_notes: str | None = None
    brands: list[CatalogueOption]
    categories: list[CatalogueOption]
    checklists: list[ChecklistOption] = Field(default_factory=list)
    images: list[AIImage] = Field(default_factory=list)

    def cache_key_payload(self) -> dict[str, Any]:
        """The request as hashed for caching: images by content hash, not bytes."""
        data = self.model_dump(mode="json", exclude={"images"})
        data["images"] = [img.sha256 for img in self.images]
        return data
