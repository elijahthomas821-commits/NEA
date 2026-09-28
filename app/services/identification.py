"""Identify a stored listing: rules → (AI when useful) → mislabel check → product match."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from app.analysis.identification.ai_merge import (
    apply_mislabel,
    is_mislabel_candidate,
    merge_ai,
)
from app.analysis.identification.rules import identify
from app.analysis.identification.types import Catalogue, IdentificationResult, ListingText
from app.analysis.matching.matcher import MatchResult, match_product
from app.config.schemas import AuthenticityConfig
from app.core.logging import get_logger
from app.models import Listing
from app.services.ai.schemas import (
    AIListingAnalysis,
    AnalysisRequest,
    CatalogueOption,
    ChecklistOption,
)
from app.services.ai.service import AIOutcome, AIService, build_images, to_identity_evidence
from app.services.catalogue import load_catalogue, load_products
from app.services.config_service import ConfigBundle
from app.services.images import read_image

log = get_logger(__name__)


@dataclass(frozen=True)
class IdentificationOutcome:
    ident: IdentificationResult
    match: MatchResult
    ai: AIOutcome | None = None
    ai_needed_for_identity: bool = False
    ai_reasons: list[str] = field(default_factory=list)
    mislabel_reasons: list[str] = field(default_factory=list)
    photo_analysis: AIListingAnalysis | None = None

    @property
    def ai_unavailable_but_needed(self) -> bool:
        return self.ai_needed_for_identity and (self.ai is None or not self.ai.usable)


def listing_text(listing: Listing) -> ListingText:
    notes = (listing.raw_payload or {}).get("operator_notes")
    return ListingText(
        title=listing.title,
        description=listing.description,
        raw_brand=listing.raw_brand,
        raw_category=listing.raw_category,
        raw_size=listing.raw_size,
        raw_colour=listing.raw_colour,
        raw_condition=listing.raw_condition,
        operator_notes=notes if isinstance(notes, str) else None,
    )


def build_analysis_request(
    text: ListingText,
    catalogue: Catalogue,
    authenticity: AuthenticityConfig,
    brand_slug: str | None,
    images: list[tuple[str, bytes]],
) -> AnalysisRequest:
    brand_slugs = [brand_slug] if brand_slug else [b.slug for b in catalogue.brands]
    checklists = [
        ChecklistOption(brand=slug, code=item.code, description=item.description)
        for slug in brand_slugs
        for item in authenticity.brand_checklists.get(slug, [])
    ]
    return AnalysisRequest(
        title=text.title,
        description=text.description,
        brand_field=text.raw_brand,
        category_field=text.raw_category,
        size_field=text.raw_size,
        condition_field=text.raw_condition,
        operator_notes=text.operator_notes,
        brands=[CatalogueOption(slug=b.slug, name=b.name) for b in catalogue.brands],
        categories=[CatalogueOption(slug=c.slug, name=c.name) for c in catalogue.categories],
        checklists=checklists if images else [],
        images=build_images(images),
    )


def identify_listing(
    session: Session,
    listing: Listing,
    bundle: ConfigBundle,
    *,
    ai: AIService | None,
    media_dir: Path,
) -> IdentificationOutcome:
    catalogue = load_catalogue(session)
    text = listing_text(listing)
    rules_cfg = bundle.identification
    ident = identify(text, catalogue, rules_cfg, bundle.sizes)

    images = [img for img in listing.images if img.storage_key][: rules_cfg.ai.max_photos]
    needs_identity = (
        ident.confidence < rules_cfg.ai.invoke_below_confidence or ident.has_contradictions
    ) and ident.category_in_scope is not False
    mislabel, mislabel_reasons = is_mislabel_candidate(
        ident, price=listing.price, image_count=len(images), rules=rules_cfg.mislabel
    )
    wants_photos = rules_cfg.ai.analyse_photos and bool(images) and ident.category_in_scope is True

    reasons: list[str] = []
    if needs_identity:
        reasons.append("rules identification uncertain")
    if mislabel:
        reasons.append("possible mislabelled listing")
    if wants_photos:
        reasons.append("photo checklist")

    outcome: AIOutcome | None = None
    photo_analysis: AIListingAnalysis | None = None
    product_hint: str | None = None
    if reasons and ai is not None and ai.enabled and rules_cfg.ai.enabled:
        image_bytes: list[tuple[str, bytes]] = []
        for img in images:
            try:
                image_bytes.append((img.sha256 or "", read_image(media_dir, img.storage_key or "")))
            except (OSError, ValueError):
                log.warning("listing_image_missing", listing_id=listing.id, image_id=img.id)
        request = build_analysis_request(
            text, catalogue, bundle.authenticity, ident.brand_slug, image_bytes
        )
        outcome = ai.analyse(request, listing_id=listing.id)
        if outcome.analysis is not None:
            evidence = to_identity_evidence(outcome.analysis)
            if needs_identity:
                ident = merge_ai(ident, evidence, catalogue, rules_cfg.ai)
            if mislabel:
                ident = apply_mislabel(ident, evidence, catalogue, rules_cfg.mislabel)
            if request.images:
                photo_analysis = outcome.analysis
            product_hint = evidence.product_hint

    brand_ids = [ident.brand_id] if ident.brand_id is not None else []
    match = match_product(
        ident, load_products(session, brand_ids), rules_cfg.matching, hint_text=product_hint
    )
    if ident.category_id is None and match.category_id is not None:
        category = catalogue.category_by_id(match.category_id)
        if category is not None:
            ident = ident.model_copy(
                update={
                    "category_id": category.id,
                    "category_slug": category.slug,
                    "category_in_scope": category.in_scope,
                    "category_confidence": match.confidence,
                    "category_source": "product",
                    "evidence": [*ident.evidence, f"category inferred from '{category.name}'"],
                }
            )
    return IdentificationOutcome(
        ident=ident,
        match=match,
        ai=outcome,
        ai_needed_for_identity=needs_identity,
        ai_reasons=reasons,
        mislabel_reasons=mislabel_reasons if mislabel else [],
        photo_analysis=photo_analysis,
    )


def apply_identification(listing: Listing, outcome: IdentificationOutcome) -> None:
    """Store the normalised fields on the listing row."""
    ident = outcome.ident
    listing.brand_id = ident.brand_id
    listing.category_id = ident.category_id
    listing.size_normalised = ident.size.normalised
    listing.size_system = ident.size.system
    listing.is_kids = ident.size.is_kids
    listing.colour = ident.colour
    listing.condition = ident.condition.value if ident.condition else None
    listing.identification_method = ident.method.value
    listing.model_text = " ".join(ident.model_tokens)[:200] or None
    listing.matched_product_id = outcome.match.product_id
    listing.match_confidence = outcome.match.confidence if outcome.match.product_id else None
