"""Combine an AI identification with the rules result.

AI output is treated as one more (capped) source of evidence. It can confirm, fill gaps or flag
a disagreement, but it can never produce a price, and it can only name brands and categories
that are in the catalogue (validated before this function is called).
"""

from __future__ import annotations

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.identification.types import Catalogue, Contradiction, IdentificationResult
from app.config.schemas import AIIdentificationRules, MislabelRules
from app.core.enums import IdentificationMethod

ONE = Decimal(1)
CAP = Decimal("0.99")


class AIIdentityEvidence(BaseModel):
    """The parts of an AI analysis that identification uses (already catalogue-validated)."""

    model_config = ConfigDict(frozen=True)

    brand_slug: str | None = None
    category_slug: str | None = None
    colour: str | None = None
    product_hint: str | None = None
    confidence: Decimal = Decimal(0)
    evidence: list[str] = Field(default_factory=list)
    # Photo-based brand evidence (for unbranded / mislabelled listings).
    photo_brand_slug: str | None = None
    photo_brand_confidence: Decimal = Decimal(0)
    photo_brand_evidence: list[str] = Field(default_factory=list)


def merge_ai(
    ident: IdentificationResult,
    ai: AIIdentityEvidence,
    catalogue: Catalogue,
    rules: AIIdentificationRules,
) -> IdentificationResult:
    ai_conf = min(ai.confidence, rules.max_confidence)
    updates: dict[str, object] = {}
    evidence = list(ident.evidence)
    contradictions = list(ident.contradictions)
    used = False

    brand = catalogue.brand_by_slug(ai.brand_slug)
    if brand is not None:
        if ident.brand_id is None:
            updates.update(
                brand_id=brand.id,
                brand_slug=brand.slug,
                brand_confidence=ai_conf.quantize(Decimal("0.001")),
                brand_source="ai",
            )
            evidence.append(f"AI identified brand '{brand.name}' (confidence {ai_conf})")
            used = True
        elif ident.brand_id == brand.id:
            boosted = (
                ident.brand_confidence
                + (ONE - ident.brand_confidence) * rules.agree_boost * ai_conf
            )
            updates["brand_confidence"] = min(CAP, boosted).quantize(Decimal("0.001"))
            evidence.append("AI agrees with the brand")
            used = True
        else:
            contradictions.append(
                Contradiction(
                    code="AI_BRAND_DISAGREES",
                    detail=f"rules found {ident.brand_slug}; AI suggests {brand.slug}",
                )
            )
            updates["brand_confidence"] = (ident.brand_confidence * rules.disagree_factor).quantize(
                Decimal("0.001")
            )
            used = True

    category = catalogue.category_by_slug(ai.category_slug)
    if category is not None:
        if ident.category_id is None:
            updates.update(
                category_id=category.id,
                category_slug=category.slug,
                category_in_scope=category.in_scope,
                category_confidence=ai_conf.quantize(Decimal("0.001")),
                category_source="ai",
            )
            evidence.append(f"AI identified category '{category.name}'")
            used = True
        elif ident.category_id == category.id:
            boosted = (
                ident.category_confidence
                + (ONE - ident.category_confidence) * rules.agree_boost * ai_conf
            )
            updates["category_confidence"] = min(CAP, boosted).quantize(Decimal("0.001"))
            used = True
        else:
            contradictions.append(
                Contradiction(
                    code="AI_CATEGORY_DISAGREES",
                    detail=f"rules found {ident.category_slug}; AI suggests {category.slug}",
                )
            )
            updates["category_confidence"] = (
                ident.category_confidence * rules.disagree_factor
            ).quantize(Decimal("0.001"))
            used = True

    if ident.colour is None and ai.colour:
        updates["colour"] = ai.colour
    if not used:
        return ident.model_copy(update={"evidence": evidence, **updates})
    method = (
        IdentificationMethod.AI
        if ident.method == IdentificationMethod.RULES and ident.brand_id is None
        else IdentificationMethod.RULES_AI
    )
    updates.update(evidence=evidence, contradictions=contradictions, method=method)
    return ident.model_copy(update=updates)


def is_mislabel_candidate(
    ident: IdentificationResult,
    *,
    price: Decimal | None,
    image_count: int,
    rules: MislabelRules,
) -> tuple[bool, list[str]]:
    """Unbranded / unknown-brand listings worth a photo check for a known brand's marks."""
    reasons: list[str] = []
    if not rules.enabled:
        return False, ["mislabel detection disabled"]
    if ident.brand_id is not None:
        return False, ["brand already identified"]
    if ident.category_in_scope is not True:
        return False, ["category not in scope"]
    if price is None or not (rules.min_price <= price <= rules.max_price):
        return False, ["price outside the mislabel price band"]
    if image_count < 1:
        return False, ["no photos"]
    if rules.require_keyword:
        text = " ".join(ident.tokens)
        keywords = [k for k in rules.keywords if f" {k} " in f" {text} "]
        if not keywords:
            return False, ["no badge/detail keywords"]
        reasons.append("keywords: " + ", ".join(keywords))
    reasons.append("unbranded listing with photos in the price band")
    return True, reasons


def apply_mislabel(
    ident: IdentificationResult,
    ai: AIIdentityEvidence,
    catalogue: Catalogue,
    rules: MislabelRules,
) -> IdentificationResult:
    """Adopt a brand seen in the photos of an unbranded listing (capped confidence)."""
    brand = catalogue.brand_by_slug(ai.photo_brand_slug)
    if brand is None or ai.photo_brand_confidence < rules.min_ai_confidence:
        return ident
    confidence = min(ai.photo_brand_confidence, rules.max_confidence).quantize(Decimal("0.001"))
    evidence = [
        *ident.evidence,
        f"photos suggest '{brand.name}' although the listing is unbranded "
        f"(confidence {confidence})",
        *(f"photo evidence: {e}" for e in ai.photo_brand_evidence[:4]),
    ]
    return ident.model_copy(
        update={
            "brand_id": brand.id,
            "brand_slug": brand.slug,
            "brand_confidence": confidence,
            "brand_source": "mislabel_ai",
            "method": IdentificationMethod.MISLABEL_AI,
            "mislabel": True,
            "evidence": evidence,
        }
    )
