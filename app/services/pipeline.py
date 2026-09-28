"""The evaluation pipeline: one listing in, one fully explained evaluation out.

    identify (rules → AI if useful → mislabel check) → match product
    → comparable sales / price guide → profit, ROI, maximum purchase price
    → sale velocity → authenticity risk → inventory exposure → deal rules
    → persist a complete, reproducible snapshot (``listing_evaluations``)

Every evaluation records the configuration versions it used, the comps and their weights,
every cost line and every reason code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.authenticity.risk import (
    AuthenticityAssessment,
    AuthenticityInputs,
    ChecklistObservation,
    SellerSignals,
    assess_authenticity,
)
from app.analysis.deals.engine import DealDecision, DealInputs, ExposureSnapshot, decide
from app.analysis.market.comps import MarketResult
from app.analysis.profit.max_price import MaxPriceResult, max_purchase_price
from app.analysis.profit.model import ProfitBreakdown, default_extras, profit_breakdown
from app.analysis.velocity.velocity import VelocityResult
from app.config.settings import Settings, get_settings
from app.core.enums import InventoryStatus, ListingStatus, ProductLevel
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.core.time import utcnow
from app.database.session import get_database
from app.models import InventoryItem, Listing, ListingEvaluation, Product
from app.services.ai.factory import build_ai_service
from app.services.ai.service import AIService
from app.services.catalogue import load_catalogue
from app.services.config_service import ConfigBundle, ConfigService
from app.services.identification import (
    IdentificationOutcome,
    apply_identification,
    identify_listing,
)
from app.services.images import find_reused_photos
from app.services.pricing import PricingOutcome, price_target
from app.services.velocity import velocity_for

log = get_logger(__name__)

PIPELINE_VERSION = "1.0.0"
UNSOLD_STATUSES = [
    InventoryStatus.ORDERED.value,
    InventoryStatus.IN_TRANSIT.value,
    InventoryStatus.RECEIVED.value,
    InventoryStatus.NEEDS_WORK.value,
    InventoryStatus.READY_TO_LIST.value,
    InventoryStatus.LISTED.value,
]


@dataclass(frozen=True)
class EvaluationContext:
    bundle: ConfigBundle
    ai: AIService | None
    media_dir: Path
    now: datetime


def exposure_snapshot(session: Session, product_id: int | None) -> ExposureSnapshot:
    cost = session.scalar(
        select(
            func.coalesce(
                func.sum(
                    InventoryItem.allocated_acquisition_cost
                    + InventoryItem.cleaning_cost
                    + InventoryItem.repair_cost
                    + InventoryItem.other_costs
                ),
                0,
            )
        ).where(InventoryItem.status.in_(UNSOLD_STATUSES))
    )
    units = 0
    if product_id is not None:
        units = int(
            session.scalar(
                select(func.count(InventoryItem.id)).where(
                    InventoryItem.status.in_(UNSOLD_STATUSES),
                    InventoryItem.product_id == product_id,
                )
            )
            or 0
        )
    return ExposureSnapshot(unsold_cost=Decimal(cost or 0), units_of_product=units)


def _seller_signals(listing: Listing) -> SellerSignals | None:
    seller = listing.seller
    if seller is None:
        return None
    return SellerSignals(
        rating=seller.rating,
        review_count=seller.review_count,
        member_since=seller.member_since,
        operator_flag=seller.operator_flag,
    )


def _checklist(
    outcome: IdentificationOutcome,
) -> tuple[list[ChecklistObservation], list[str], str | None]:
    analysis = outcome.photo_analysis
    if analysis is None:
        return [], [], None
    brand = outcome.ident.brand_slug
    observations = [
        ChecklistObservation(code=item.code, result=item.result, note=item.note)
        for item in analysis.checklist
        if item.brand == brand
    ]
    return observations, list(analysis.concerns), analysis.photo_quality


def _market_details(market: MarketResult | None) -> dict[str, Any]:
    if market is None:
        return {}

    def comp(c: Any) -> dict[str, Any]:
        return {
            "sale_id": c.sale_id,
            "level": c.level.value,
            "price": str(c.original_price),
            "currency": c.original_currency,
            "adjusted": str(c.adjusted_price.quantize(Decimal("0.01"))),
            "weight": str(c.weight.quantize(Decimal("0.0001"))),
            "condition_ratio": str(c.condition_ratio.quantize(Decimal("0.0001"))),
            "size_ratio": str(c.size_ratio.quantize(Decimal("0.0001"))),
            "haircut": str(c.haircut),
        }

    return {
        "level": market.level.value if market.level else None,
        "sample_size": market.sample_size,
        "effective_sample_size": str(market.effective_sample_size),
        "percentiles": {k: str(v.quantize(Decimal("0.01"))) for k, v in market.percentiles.items()},
        "dispersion": str(market.dispersion) if market.dispersion is not None else None,
        "confidence": str(market.confidence),
        "comps": [comp(c) for c in market.comps],
        "outliers": [comp(c) for c in market.outliers],
        "excluded": [e.model_dump(mode="json") for e in market.excluded],
        "attempts": [a.model_dump(mode="json") for a in market.attempts],
    }


def evaluate_listing(
    session: Session, listing: Listing, ctx: EvaluationContext, *, trigger: str
) -> ListingEvaluation:
    bundle = ctx.bundle
    catalogue = load_catalogue(session)

    identification = identify_listing(session, listing, bundle, ai=ctx.ai, media_dir=ctx.media_dir)
    apply_identification(listing, identification)
    ident, match = identification.ident, identification.match

    product = session.get(Product, match.product_id) if match.product_id else None
    product_is_specific = (
        product is not None and product.level != ProductLevel.BRAND_CATEGORY_GENERIC.value
    )
    in_scope = ident.category_in_scope is True
    price = listing.price
    currency = listing.currency or bundle.deal_rules.currency

    pricing: PricingOutcome | None = None
    velocity = VelocityResult()
    if ident.brand_id is not None and ident.category_id is not None and in_scope:
        pricing = price_target(
            session,
            bundle,
            catalogue,
            brand_id=ident.brand_id,
            category_id=ident.category_id,
            product_id=match.product_id,
            size=ident.size.normalised,
            colour=ident.colour,
            condition=ident.condition,
            currency=currency,
            match_confidence=match.confidence,
            as_of=ctx.now,
        )
        velocity = velocity_for(
            session,
            brand_id=ident.brand_id,
            category_id=ident.category_id,
            product_id=match.product_id,
            product_is_generic=not product_is_specific,
            as_of=ctx.now,
            rules=bundle.market.velocity,
        )
    estimate = pricing.estimate if pricing else None

    profit: ProfitBreakdown | None = None
    max_price: MaxPriceResult | None = None
    if estimate is not None and currency == bundle.fees.currency:
        basis = (
            estimate.expected if bundle.deal_rules.resale_basis == "expected" else estimate.quick
        )
        extras = default_extras(bundle.fees)
        max_price = max_purchase_price(
            basis,
            bundle.fees,
            min_profit=bundle.deal_rules.min_profit,
            min_roi=bundle.deal_rules.min_roi,
            price_cap=bundle.deal_rules.max_purchase_price,
            capital_cap=bundle.deal_rules.max_capital_per_item,
            extras=extras,
        )
        if price is not None:
            profit = profit_breakdown(price, basis, bundle.fees, extras=extras)

    reused = find_reused_photos(
        session, listing, max_distance=bundle.authenticity.duplicate_phash_max_distance
    )
    checklist, ai_concerns, photo_quality = _checklist(identification)
    brand_entry = catalogue.brand_by_id(ident.brand_id)
    authenticity: AuthenticityAssessment | None = None
    if ident.brand_id is not None:
        text = " ".join(
            filter(
                None,
                [
                    listing.title,
                    listing.description,
                    (listing.raw_payload or {}).get("operator_notes"),
                ],
            )
        )
        authenticity = assess_authenticity(
            AuthenticityInputs(
                brand_slug=ident.brand_slug,
                brand_base_risk=brand_entry.base_risk if brand_entry else Decimal("0.3"),
                price=price,
                comps_median=estimate.expected if estimate and estimate.basis == "comps" else None,
                text=text,
                replica_terms=ident.replica_terms,
                seller=_seller_signals(listing),
                photo_count=len(listing.images),
                reused_photo_matches=len(reused),
                mislabel=ident.mislabel,
                contradiction_count=len(ident.contradictions),
                checklist=checklist,
                photo_quality=photo_quality,
                ai_concerns=ai_concerns,
                as_of=ctx.now.date(),
            ),
            bundle.authenticity,
        )

    exposure = exposure_snapshot(session, match.product_id if product_is_specific else None)
    decision: DealDecision = decide(
        DealInputs(
            listing_status=ListingStatus(listing.status),
            price=price,
            currency=listing.currency,
            brand_known=ident.brand_id is not None,
            category_known=ident.category_id is not None,
            category_in_scope=ident.category_in_scope,
            is_kids=ident.size.is_kids,
            replica_terms=ident.replica_terms,
            damage_terms=ident.damage_terms,
            contradictions=[c.detail for c in ident.contradictions],
            mislabel=ident.mislabel,
            product_is_specific=product_is_specific,
            product_confidence=match.confidence,
            estimate=estimate,
            profit=profit,
            max_price=max_price,
            velocity=velocity,
            authenticity=authenticity,
            exposure=exposure,
            ai_unavailable_but_needed=identification.ai_unavailable_but_needed,
            possible_duplicate=listing.possible_duplicate_of is not None,
        ),
        bundle.deal_rules,
    )

    ai = identification.ai
    details: dict[str, Any] = {
        "identification": ident.model_dump(mode="json", exclude={"tokens"}),
        "match": match.model_dump(mode="json"),
        "product_name": product.canonical_name if product else None,
        "ai": {
            "status": ai.status if ai else "not_requested",
            "reasons": identification.ai_reasons,
            "cost_usd": str(ai.cost_usd) if ai else "0",
            "request_id": ai.request_id if ai else None,
            "detail": ai.detail if ai else None,
        },
        "mislabel_reasons": identification.mislabel_reasons,
        "market": _market_details(pricing.market if pricing else None),
        "estimate": estimate.model_dump(mode="json") if estimate else None,
        "profit": profit.lines() if profit else None,
        "max_price": max_price.model_dump(mode="json") if max_price else None,
        "velocity": velocity.model_dump(mode="json"),
        "authenticity": authenticity.model_dump(mode="json") if authenticity else None,
        "reused_photos": reused,
        "exposure": exposure.model_dump(mode="json"),
        "reasons": [r.model_dump(mode="json") for r in decision.reasons],
    }
    evaluation = ListingEvaluation(
        listing_id=listing.id,
        evaluated_at=ctx.now,
        trigger=trigger,
        pipeline_version=PIPELINE_VERSION,
        config_version_ids=bundle.version_ids,
        price_at_evaluation=price,
        currency=listing.currency,
        brand_id=ident.brand_id,
        category_id=ident.category_id,
        product_id=match.product_id,
        identification_method=ident.method.value,
        identification_confidence=ident.confidence,
        match_confidence=match.confidence if match.product_id else None,
        mislabel_flag=ident.mislabel,
        estimate_basis=estimate.basis if estimate else None,
        comp_level=estimate.level.value if estimate else None,
        comp_sample_size=estimate.sample_size if estimate else 0,
        comp_effective_sample_size=(
            estimate.effective_sample_size.quantize(Decimal("0.01")) if estimate else Decimal(0)
        ),
        quick_sale_price=estimate.quick.quantize(Decimal("0.01")) if estimate else None,
        expected_sale_price=estimate.expected.quantize(Decimal("0.01")) if estimate else None,
        optimistic_sale_price=estimate.optimistic.quantize(Decimal("0.01")) if estimate else None,
        estimate_confidence=estimate.confidence if estimate else None,
        median_days_to_sale=velocity.median_days_to_sale,
        liquidity_score=velocity.liquidity_score,
        total_acquisition_cost=profit.acquisition.total if profit else None,
        expected_selling_costs=profit.selling.total if profit else None,
        expected_profit=profit.net_profit.quantize(Decimal("0.01")) if profit else None,
        expected_roi=profit.roi.quantize(Decimal("0.0001"))
        if profit and profit.roi is not None
        else None,
        max_purchase_price=max_price.price if max_price else None,
        authenticity_risk_score=authenticity.risk_score if authenticity else None,
        authenticity_confidence=authenticity.confidence if authenticity else None,
        decision=decision.decision.value,
        reason_codes=decision.codes,
        details=details,
        ai_used=ai is not None and ai.usable,
        ai_cost_usd=ai.cost_usd if ai else Decimal(0),
    )
    session.add(evaluation)
    session.flush()
    log.info(
        "listing_evaluated",
        listing_id=listing.id,
        evaluation_id=evaluation.id,
        decision=evaluation.decision,
        reasons=decision.codes,
    )
    return evaluation


def build_context(
    session: Session, *, settings: Settings | None = None, ai: AIService | None = None,
    now: datetime | None = None,
) -> EvaluationContext:  # fmt: skip
    settings = settings or get_settings()
    return EvaluationContext(
        bundle=ConfigService(session).bundle(),
        ai=ai if ai is not None else build_ai_service(settings, get_database()),
        media_dir=settings.media_dir,
        now=now or utcnow(),
    )


def evaluate_listing_by_id(
    session: Session,
    listing_id: int,
    *,
    trigger: str,
    context: EvaluationContext | None = None,
) -> ListingEvaluation:
    listing = session.get(Listing, listing_id)
    if listing is None:
        raise NotFoundError(f"listing {listing_id} not found")
    ctx = context or build_context(session)
    return evaluate_listing(session, listing, ctx, trigger=trigger)
