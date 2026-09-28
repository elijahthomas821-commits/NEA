"""End-to-end evaluation: ingest → identify → price → profit → risk → decision → snapshot."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest

from app.core.enums import Decision
from app.core.time import FixedClock
from app.services.ai.fake import FakeProvider
from app.services.ai.schemas import AIChecklistItem, AIListingAnalysis
from app.services.ai.service import AIService
from app.services.config_service import ConfigService
from app.services.images import add_listing_image
from app.services.ingestion import ingest_listing
from app.services.pipeline import EvaluationContext, evaluate_listing
from tests.factories import NOW, image_bytes, raw_listing, raw_seller
from tests.integration.test_market_data import raw as raw_sale

pytestmark = pytest.mark.integration


def seed_comps(recorder, n=10, price="110", **overrides):
    for i in range(n):
        recorder(
            raw_sale(
                sale_price=Decimal(price) + Decimal(i % 3) - 1,
                source_ref=f"pipe:{price}:{i}",
                listed_at=NOW - timedelta(days=15 + i),
                sold_at=NOW - timedelta(days=3 + i),
                **overrides,
            )
        )


def listing_for(db_session, **overrides):
    data = {
        "title": "Stone Island garment dyed crewneck sweatshirt navy L",
        "raw_brand": "Stone Island",
        "raw_category": "Sweatshirts",
        "raw_size": "L",
        "raw_condition": "Very good",
        "price": Decimal("45.00"),
    }
    data.update(overrides)
    return ingest_listing(db_session, raw_listing(**data), source="api", now=NOW).listing


def context(db_session, tmp_path, ai=None):
    return EvaluationContext(
        bundle=ConfigService(db_session).bundle(), ai=ai, media_dir=tmp_path, now=NOW
    )


def test_no_market_data_is_rejected_with_reason(db_session, tmp_path):
    listing = listing_for(db_session)
    evaluation = evaluate_listing(
        db_session, listing, context(db_session, tmp_path), trigger="ingest"
    )
    assert evaluation.decision == Decision.REJECTED.value
    assert "INSUFFICIENT_MARKET_DATA" in evaluation.reason_codes
    assert evaluation.expected_sale_price is None
    assert evaluation.details["market"]["attempts"]
    # The listing itself now carries the normalised identification.
    assert listing.brand_id is not None
    assert listing.size_normalised == "L"
    assert listing.matched_product_id is not None
    assert set(evaluation.config_version_ids) >= {"deal_rules", "fees", "market"}


def test_priced_listing_without_photos_goes_to_review(db_session, tmp_path, recorder):
    seed_comps(recorder)
    listing = listing_for(db_session)
    evaluation = evaluate_listing(
        db_session, listing, context(db_session, tmp_path), trigger="ingest"
    )
    assert evaluation.decision == Decision.REVIEW.value, evaluation.reason_codes
    assert "AUTH_NEEDS_EVIDENCE" in evaluation.reason_codes
    assert evaluation.comp_level == "L1"
    assert Decimal("105") < evaluation.expected_sale_price < Decimal("115")
    assert evaluation.expected_profit > Decimal("25")
    assert evaluation.max_purchase_price > listing.price
    assert evaluation.median_days_to_sale is not None
    profit = evaluation.details["profit"]
    assert profit["purchase_price"] == "45.00"
    assert profit["buyer_fee"] == "2.95"
    assert len(evaluation.details["market"]["comps"]) == 10
    assert evaluation.details["authenticity"]["recommended_checks"][0].startswith(
        "Ask the seller for more photos"
    )


def test_strong_evidence_reaches_high_priority(db_session, tmp_path, recorder, test_db):
    seed_comps(recorder)
    listing = listing_for(db_session, seller=raw_seller(rating=Decimal("4.9"), review_count=180))
    for seed in range(4):
        add_listing_image(
            db_session, listing, image_bytes(seed=40 + seed), media_dir=tmp_path,
            max_bytes=5_000_000, max_images=10,
        )  # fmt: skip
    db_session.refresh(listing)
    checklist = [
        AIChecklistItem(brand="stone-island", code=code, result="observed", note="clear")
        for code in ("compass_badge", "badge_back", "authenticity_label", "care_labels")
    ]
    provider = FakeProvider(
        lambda r: AIListingAnalysis(
            brand="stone-island",
            category="sweatshirts",
            identification_confidence=Decimal("0.9"),
            photo_brand="stone-island",
            photo_brand_confidence=Decimal("0.9"),
            checklist=checklist,
            photo_quality="good",
        )
    )
    ai = AIService(
        provider, session_scope=test_db.session_scope, daily_budget_usd=Decimal(1),
        monthly_budget_usd=Decimal(10), clock=FixedClock(NOW),
    )  # fmt: skip
    evaluation = evaluate_listing(
        db_session, listing, context(db_session, tmp_path, ai), trigger="ingest"
    )
    assert evaluation.decision == Decision.HIGH_PRIORITY.value, evaluation.details["reasons"]
    assert evaluation.ai_used
    assert evaluation.authenticity_risk_score < Decimal("0.25")
    assert evaluation.authenticity_confidence >= Decimal("0.5")


def test_overpriced_listing_rejected(db_session, tmp_path, recorder):
    seed_comps(recorder)
    listing = listing_for(db_session, price=Decimal("95.00"))
    evaluation = evaluate_listing(
        db_session, listing, context(db_session, tmp_path), trigger="ingest"
    )
    assert evaluation.decision == Decision.REJECTED.value
    assert "PROFIT_BELOW_MIN" in evaluation.reason_codes
    assert evaluation.expected_profit < Decimal(25)


def test_replica_listing_rejected(db_session, tmp_path, recorder):
    seed_comps(recorder)
    listing = listing_for(db_session, title="Stone Island crewneck 1:1 replica navy L")
    evaluation = evaluate_listing(
        db_session, listing, context(db_session, tmp_path), trigger="ingest"
    )
    assert evaluation.decision == Decision.REJECTED.value
    assert "REPLICA_LANGUAGE" in evaluation.reason_codes


def test_unknown_brand_rejected(db_session, tmp_path):
    listing = listing_for(
        db_session, title="Nike tech fleece hoodie", raw_brand="Nike", raw_category="Hoodies"
    )
    evaluation = evaluate_listing(
        db_session, listing, context(db_session, tmp_path), trigger="ingest"
    )
    assert evaluation.decision == Decision.REJECTED.value
    assert "BRAND_UNKNOWN" in evaluation.reason_codes
    assert evaluation.details["authenticity"] is None


def test_price_guide_bootstrap_reaches_review_at_best(db_session, tmp_path):
    service = ConfigService(db_session)
    from app.core.enums import ConfigKind
    from app.services.audit import Actor

    service.create_version(
        ConfigKind.PRICE_GUIDE,
        {
            "entries": [
                {
                    "brand": "stone-island",
                    "category": "sweatshirts",
                    "low": "90",
                    "typical": "110",
                    "high": "130",
                }
            ]
        },
        actor=Actor.system("test"),
    )
    listing = listing_for(db_session)
    evaluation = evaluate_listing(
        db_session, listing, context(db_session, tmp_path), trigger="ingest"
    )
    assert evaluation.estimate_basis == "price_guide"
    assert evaluation.comp_level == "GUIDE"
    assert evaluation.decision in (Decision.REVIEW.value, Decision.REJECTED.value)
    assert (
        "ESTIMATE_FROM_PRICE_GUIDE" in evaluation.reason_codes
        or "AUTH_NEEDS_EVIDENCE" in evaluation.reason_codes
    )


def test_reevaluation_is_reproducible_from_stored_versions(db_session, tmp_path, recorder):
    seed_comps(recorder)
    listing = listing_for(db_session)
    first = evaluate_listing(db_session, listing, context(db_session, tmp_path), trigger="ingest")
    rebuilt = ConfigService(db_session).bundle_for_versions(first.config_version_ids)
    again = evaluate_listing(
        db_session, listing,
        EvaluationContext(bundle=rebuilt, ai=None, media_dir=tmp_path, now=first.evaluated_at),
        trigger="backfill",
    )  # fmt: skip
    assert (again.decision, again.expected_profit, again.max_purchase_price) == (
        first.decision, first.expected_profit, first.max_purchase_price,
    )  # fmt: skip
