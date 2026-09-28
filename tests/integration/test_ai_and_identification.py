from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.core.enums import IdentificationMethod
from app.core.time import FixedClock
from app.models import AIRequest, Listing
from app.services.ai.fake import FakeProvider
from app.services.ai.provider import AIUnavailableError
from app.services.ai.schemas import (
    AIChecklistItem,
    AIListingAnalysis,
    AnalysisRequest,
    CatalogueOption,
    ChecklistOption,
)
from app.services.ai.service import AIService
from app.services.identification import apply_identification, identify_listing
from app.services.images import add_listing_image
from app.services.ingestion import ingest_listing
from tests.factories import NOW, image_bytes, raw_listing

pytestmark = pytest.mark.integration


def analysis(**overrides) -> AIListingAnalysis:
    data = {
        "brand": "unknown",
        "category": "unknown",
        "identification_confidence": Decimal("0.5"),
        "photo_quality": "none",
    }
    data.update(overrides)
    return AIListingAnalysis(**data)


def simple_request(**overrides) -> AnalysisRequest:
    data = {
        "title": "Overshirt",
        "brands": [CatalogueOption(slug="stone-island", name="Stone Island")],
        "categories": [CatalogueOption(slug="jackets", name="Jackets")],
        "checklists": [
            ChecklistOption(brand="stone-island", code="compass_badge", description="x")
        ],
    }
    data.update(overrides)
    return AnalysisRequest(**data)


@pytest.fixture
def clock():
    return FixedClock(NOW)


def make_service(test_db, provider, clock, daily="1.00", monthly="10.00") -> AIService:
    return AIService(
        provider,
        session_scope=test_db.session_scope,
        daily_budget_usd=Decimal(daily),
        monthly_budget_usd=Decimal(monthly),
        clock=clock,
    )


class TestAIService:
    def test_disabled_without_provider(self, test_db, clock):
        outcome = make_service(test_db, None, clock).analyse(simple_request(), listing_id=None)
        assert outcome.status == "disabled"
        assert not outcome.usable

    def test_success_is_recorded_and_then_cached(self, test_db, db_session, clock):
        provider = FakeProvider(lambda r: analysis(brand="stone-island"))
        service = make_service(test_db, provider, clock)
        first = service.analyse(simple_request(), listing_id=None)
        assert first.status == "ok"
        assert first.cost_usd > 0
        row = db_session.get(AIRequest, first.request_id)
        assert row.status == "ok"
        assert row.response["brand"] == "stone-island"
        assert row.input_tokens == 1000

        second = service.analyse(simple_request(), listing_id=None)
        assert second.status == "cached"
        assert second.analysis == first.analysis
        assert len(provider.calls) == 1

    def test_different_images_are_not_cached_together(self, test_db, clock):
        from app.services.ai.schemas import AIImage

        provider = FakeProvider(lambda r: analysis())
        service = make_service(test_db, provider, clock)
        img = AIImage(sha256="a" * 64, media_type="image/jpeg", data=b"x")
        service.analyse(simple_request(), listing_id=None)
        service.analyse(simple_request(images=[img]), listing_id=None)
        assert len(provider.calls) == 2

    def test_outputs_are_sanitised_to_the_catalogue(self, test_db, clock):
        provider = FakeProvider(
            lambda r: analysis(
                brand="gucci",
                photo_brand="supreme",
                colour="chartreuse",
                checklist=[
                    AIChecklistItem(brand="stone-island", code="compass_badge", result="observed"),
                    AIChecklistItem(brand="stone-island", code="made_up", result="concern"),
                ],
            )
        )
        outcome = make_service(test_db, provider, clock).analyse(simple_request(), listing_id=None)
        assert outcome.analysis.brand == "unknown"
        assert outcome.analysis.photo_brand == "unknown"
        assert outcome.analysis.colour == "unknown"
        assert [c.code for c in outcome.analysis.checklist] == ["compass_badge"]

    @pytest.mark.parametrize("status", ["error", "timeout", "invalid_response"])
    def test_provider_failure_recorded(self, test_db, db_session, clock, status):
        provider = FakeProvider(
            lambda r: analysis(), errors=[AIUnavailableError(status, "provider said no")]
        )
        outcome = make_service(test_db, provider, clock).analyse(simple_request(), listing_id=None)
        assert outcome.status == status
        assert not outcome.usable
        assert db_session.get(AIRequest, outcome.request_id).status == status

    def test_daily_budget_blocks_calls(self, test_db, db_session, clock):
        db_session.add(
            AIRequest(
                purpose="listing_analysis", provider="fake", model="m", input_hash="x" * 64,
                prompt_version="t", status="ok", cost_usd=Decimal("1.50"),
                created_at=NOW - timedelta(hours=1),
            )
        )  # fmt: skip
        db_session.commit()
        provider = FakeProvider(lambda r: analysis())
        outcome = make_service(test_db, provider, clock).analyse(simple_request(), listing_id=None)
        assert outcome.status == "budget_exceeded"
        assert provider.calls == []

    def test_yesterdays_spend_does_not_count_today(self, test_db, db_session, clock):
        db_session.add(
            AIRequest(
                purpose="listing_analysis", provider="fake", model="m", input_hash="y" * 64,
                prompt_version="t", status="ok", cost_usd=Decimal("1.50"),
                created_at=NOW - timedelta(days=1),
            )
        )  # fmt: skip
        db_session.commit()
        outcome = make_service(test_db, FakeProvider(lambda r: analysis()), clock).analyse(
            simple_request(), listing_id=None
        )
        assert outcome.status == "ok"


@pytest.fixture
def media(tmp_path):
    return tmp_path / "media"


def _listing(db_session, **overrides) -> Listing:
    return ingest_listing(db_session, raw_listing(**overrides), source="api", now=NOW).listing


class TestIdentificationService:
    def test_rules_only(self, db_session, config_bundle, media):
        listing = _listing(
            db_session, title="Stone Island Crinkle Reps jacket navy L", raw_category="Jackets"
        )
        outcome = identify_listing(db_session, listing, config_bundle, ai=None, media_dir=media)
        assert outcome.ident.brand_slug == "stone-island"
        assert outcome.match.method == "alias"
        assert outcome.ai is None
        apply_identification(listing, outcome)
        db_session.flush()
        assert listing.matched_product_id == outcome.match.product_id
        assert listing.size_normalised == "L"
        assert listing.colour == "navy"
        assert listing.condition == "very_good"

    def test_confident_listing_without_photos_skips_ai(
        self, db_session, config_bundle, media, test_db, clock
    ):
        provider = FakeProvider(lambda r: analysis())
        listing = _listing(db_session, title="Stone Island crewneck sweatshirt")
        outcome = identify_listing(
            db_session, listing, config_bundle,
            ai=make_service(test_db, provider, clock), media_dir=media,
        )  # fmt: skip
        assert provider.calls == []
        assert outcome.ai is None

    def test_uncertain_listing_uses_ai(self, db_session, config_bundle, media, test_db, clock):
        provider = FakeProvider(
            lambda r: analysis(
                brand="moncler", category="jackets", identification_confidence=Decimal("0.9")
            )
        )
        listing = _listing(
            db_session, title="Black down puffer jacket", raw_brand=None, raw_category=None,
            description="Maya style? bought in Milan",
        )  # fmt: skip
        outcome = identify_listing(
            db_session, listing, config_bundle,
            ai=make_service(test_db, provider, clock), media_dir=media,
        )  # fmt: skip
        assert len(provider.calls) == 1
        assert outcome.ident.brand_slug == "moncler"
        assert outcome.ident.method is IdentificationMethod.AI
        assert outcome.ident.brand_confidence <= Decimal("0.80")

    def test_ai_failure_falls_back_to_rules(self, db_session, config_bundle, media, test_db, clock):
        provider = FakeProvider(
            lambda r: analysis(), errors=[AIUnavailableError("timeout", "slow")]
        )
        listing = _listing(db_session, title="Black puffer jacket", raw_brand=None)
        outcome = identify_listing(
            db_session, listing, config_bundle,
            ai=make_service(test_db, provider, clock), media_dir=media,
        )  # fmt: skip
        assert outcome.ai.status == "timeout"
        assert outcome.ai_unavailable_but_needed
        assert outcome.ident.brand_id is None

    def test_mislabelled_listing_detected_from_photos(
        self, db_session, config_bundle, media, test_db, clock
    ):
        provider = FakeProvider(
            lambda r: analysis(
                category="jackets",
                photo_brand="stone-island",
                photo_brand_confidence=Decimal("0.9"),
                photo_brand_evidence=["compass badge on sleeve"],
                photo_quality="good",
            )
        )
        listing = _listing(
            db_session, title="Navy overshirt with arm badge", raw_brand="Unbranded",
            raw_category="Jackets", price=Decimal("25.00"),
        )  # fmt: skip
        add_listing_image(
            db_session, listing, image_bytes(seed=11), media_dir=media,
            max_bytes=5_000_000, max_images=5,
        )  # fmt: skip
        db_session.refresh(listing)
        outcome = identify_listing(
            db_session, listing, config_bundle,
            ai=make_service(test_db, provider, clock), media_dir=media,
        )  # fmt: skip
        assert outcome.ident.mislabel
        assert outcome.ident.brand_slug == "stone-island"
        assert outcome.ident.brand_confidence <= Decimal("0.60")
        assert outcome.photo_analysis is not None
        sent = provider.calls[0]
        assert len(sent.images) == 1
        # Unknown brand → checklists for every brand are offered.
        assert {c.brand for c in sent.checklists} >= {"stone-island", "moncler"}

    def test_photo_checklist_for_known_brand(
        self, db_session, config_bundle, media, test_db, clock
    ):
        provider = FakeProvider(lambda r: analysis(brand="stone-island", photo_quality="good"))
        listing = _listing(db_session, title="Stone Island crewneck sweatshirt")
        add_listing_image(
            db_session, listing, image_bytes(seed=12), media_dir=media,
            max_bytes=5_000_000, max_images=5,
        )  # fmt: skip
        db_session.refresh(listing)
        outcome = identify_listing(
            db_session, listing, config_bundle,
            ai=make_service(test_db, provider, clock), media_dir=media,
        )  # fmt: skip
        assert outcome.ai_reasons == ["photo checklist"]
        assert {c.brand for c in provider.calls[0].checklists} == {"stone-island"}
        assert (
            db_session.scalar(
                select(AIRequest.listing_id).where(AIRequest.id == outcome.ai.request_id)
            )
            == listing.id
        )
