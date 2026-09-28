from __future__ import annotations

import threading
from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.enums import ListingStatus
from app.core.errors import InvalidStateError, NotFoundError, ValidationFailedError
from app.models import Listing, ListingStatusHistory, PriceHistory, Seller
from app.services.ingestion import ingest_listing, update_listing
from tests.factories import NOW, next_id, raw_listing, raw_seller

pytestmark = pytest.mark.integration


def _history(session, listing_id):
    return list(
        session.scalars(
            select(PriceHistory)
            .where(PriceHistory.listing_id == listing_id)
            .order_by(PriceHistory.observed_at)
        )
    )


class TestIngest:
    def test_creates_listing_with_history(self, db_session):
        result = ingest_listing(db_session, raw_listing(), source="api", now=NOW)
        assert result.created
        assert result.needs_evaluation
        listing = result.listing
        assert listing.status == "active"
        assert listing.first_seen_at == NOW
        history = _history(db_session, listing.id)
        assert [(h.price, h.previous_price) for h in history] == [(Decimal("45.00"), None)]
        statuses = db_session.scalars(
            select(ListingStatusHistory).where(ListingStatusHistory.listing_id == listing.id)
        ).all()
        assert [(s.from_status, s.to_status) for s in statuses] == [(None, "active")]

    def test_resubmitting_same_listing_is_idempotent(self, db_session):
        raw = raw_listing()
        first = ingest_listing(db_session, raw, source="api", now=NOW)
        second = ingest_listing(db_session, raw, source="api", now=NOW + timedelta(hours=1))
        assert not second.created
        assert second.listing.id == first.listing.id
        assert not second.needs_evaluation
        assert second.listing.last_seen_at == NOW + timedelta(hours=1)
        assert len(_history(db_session, first.listing.id)) == 1
        count = db_session.scalar(
            select(func.count(Listing.id)).where(Listing.external_id == raw.external_id)
        )
        assert count == 1

    def test_price_change_appends_history(self, db_session):
        raw = raw_listing(price=Decimal("50.00"))
        first = ingest_listing(db_session, raw, source="api", now=NOW)
        changed = raw.model_copy(update={"price": Decimal("42.50")})
        result = ingest_listing(db_session, changed, source="api", now=NOW + timedelta(days=1))
        assert result.price_changed
        assert result.needs_evaluation
        history = _history(db_session, first.listing.id)
        assert [(h.price, h.previous_price) for h in history] == [
            (Decimal("50.00"), None),
            (Decimal("42.50"), Decimal("50.00")),
        ]

    def test_missing_price_is_stored_and_later_filled(self, db_session):
        raw = raw_listing(price=None, currency=None)
        result = ingest_listing(db_session, raw, source="api", now=NOW)
        assert result.listing.price is None
        assert _history(db_session, result.listing.id) == []
        filled = ingest_listing(
            db_session,
            raw.model_copy(update={"price": Decimal("30"), "currency": "GBP"}),
            source="api",
            now=NOW + timedelta(minutes=5),
        )
        assert filled.price_changed
        assert [h.previous_price for h in _history(db_session, result.listing.id)] == [None]

    def test_partial_resubmission_does_not_erase_fields(self, db_session):
        raw = raw_listing(description="Worn twice, badge included")
        ingest_listing(db_session, raw, source="api", now=NOW)
        sparse = raw.model_copy(update={"description": None, "raw_size": None})
        result = ingest_listing(db_session, sparse, source="api", now=NOW + timedelta(hours=1))
        assert result.listing.description == "Worn twice, badge included"
        assert result.listing.raw_size == "L"
        assert not result.content_changed

    def test_content_change_detected(self, db_session):
        raw = raw_listing()
        ingest_listing(db_session, raw, source="api", now=NOW)
        edited = raw.model_copy(update={"title": raw.title + " - genuine"})
        result = ingest_listing(db_session, edited, source="api", now=NOW + timedelta(hours=1))
        assert result.content_changed
        assert result.needs_evaluation

    def test_status_change_recorded_and_sold_not_reevaluated(self, db_session):
        raw = raw_listing()
        ingest_listing(db_session, raw, source="api", now=NOW)
        result = ingest_listing(
            db_session, raw.model_copy(update={"status": "sold"}), source="api", now=NOW
        )
        assert result.status_changed
        assert not result.needs_evaluation
        transitions = db_session.execute(
            select(ListingStatusHistory.from_status, ListingStatusHistory.to_status)
            .where(ListingStatusHistory.listing_id == result.listing.id)
            .order_by(ListingStatusHistory.id)
        ).all()
        assert [tuple(t) for t in transitions] == [(None, "active"), ("active", "sold")]

    def test_seller_upserted_and_updated(self, db_session):
        seller = raw_seller(review_count=3)
        ingest_listing(db_session, raw_listing(seller=seller), source="api", now=NOW)
        updated = seller.model_copy(update={"review_count": 5})
        ingest_listing(db_session, raw_listing(seller=updated), source="api", now=NOW)
        rows = db_session.scalars(
            select(Seller).where(Seller.external_seller_id == seller.external_seller_id)
        ).all()
        assert len(rows) == 1
        assert rows[0].review_count == 5

    def test_unknown_marketplace(self, db_session):
        with pytest.raises(ValidationFailedError, match="unknown marketplace"):
            ingest_listing(db_session, raw_listing(marketplace="nope"), source="api", now=NOW)

    def test_relisted_item_flagged_as_possible_duplicate(self, db_session):
        seller = raw_seller()
        first = ingest_listing(
            db_session, raw_listing(seller=seller, title="Stone Island Crinkle Reps"),
            source="api", now=NOW,
        )  # fmt: skip
        second = ingest_listing(
            db_session, raw_listing(seller=seller, title="stone island crinkle reps!"),
            source="api", now=NOW + timedelta(days=2),
        )  # fmt: skip
        assert second.listing.possible_duplicate_of == first.listing.id

    def test_different_title_not_duplicate(self, db_session):
        seller = raw_seller()
        ingest_listing(db_session, raw_listing(seller=seller, title="A"), source="api", now=NOW)
        other = ingest_listing(
            db_session, raw_listing(seller=seller, title="B"), source="api", now=NOW
        )
        assert other.listing.possible_duplicate_of is None


class TestManualUpdate:
    def test_price_drop(self, db_session):
        listing = ingest_listing(db_session, raw_listing(), source="api", now=NOW).listing
        result = update_listing(db_session, listing.id, now=NOW, price=Decimal("39.99"))
        assert result.price_changed
        assert listing.price == Decimal("39.99")

    def test_mark_sold(self, db_session):
        listing = ingest_listing(db_session, raw_listing(), source="api", now=NOW).listing
        result = update_listing(
            db_session, listing.id, now=NOW, status=ListingStatus.SOLD, note="saw it sold"
        )
        assert result.status_changed
        note = db_session.scalar(
            select(ListingStatusHistory.note).where(
                ListingStatusHistory.listing_id == listing.id,
                ListingStatusHistory.to_status == "sold",
            )
        )
        assert note == "saw it sold"

    def test_removed_cannot_be_sold(self, db_session):
        listing = ingest_listing(db_session, raw_listing(), source="api", now=NOW).listing
        update_listing(db_session, listing.id, now=NOW, status=ListingStatus.REMOVED)
        with pytest.raises(InvalidStateError):
            update_listing(db_session, listing.id, now=NOW, status=ListingStatus.SOLD)

    def test_missing_listing(self, db_session):
        with pytest.raises(NotFoundError):
            update_listing(db_session, 999999, now=NOW, price=Decimal("1"))

    def test_price_without_any_currency(self, db_session):
        listing = ingest_listing(
            db_session, raw_listing(price=None, currency=None), source="api", now=NOW
        ).listing
        with pytest.raises(ValidationFailedError):
            update_listing(db_session, listing.id, now=NOW, price=Decimal("10"))


@pytest.fixture
def committed_cleanup(engine):
    """For tests that must commit (concurrency); removes their rows afterwards."""
    external_ids: list[str] = []
    yield external_ids
    with Session(bind=engine) as session:
        listing_ids = select(Listing.id).where(Listing.external_id.in_(external_ids))
        session.execute(delete(PriceHistory).where(PriceHistory.listing_id.in_(listing_ids)))
        session.execute(
            delete(ListingStatusHistory).where(ListingStatusHistory.listing_id.in_(listing_ids))
        )
        session.execute(delete(Listing).where(Listing.external_id.in_(external_ids)))
        session.commit()


def test_concurrent_duplicate_submissions_create_one_row(engine, committed_cleanup):
    external_id = next_id("77")
    committed_cleanup.append(external_id)
    raw = raw_listing(external_id=external_id)
    barrier = threading.Barrier(4)
    outcomes: list[bool] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            with Session(bind=engine) as session:
                barrier.wait(timeout=10)
                result = ingest_listing(session, raw, source="api", now=NOW)
                session.commit()
                with lock:
                    outcomes.append(result.created)
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert errors == []
    assert sorted(outcomes) == [False, False, False, True]
    with Session(bind=engine) as session:
        rows = session.scalar(
            select(func.count(Listing.id)).where(Listing.external_id == external_id)
        )
        history = session.scalar(
            select(func.count(PriceHistory.id))
            .join(Listing, Listing.id == PriceHistory.listing_id)
            .where(Listing.external_id == external_id)
        )
    assert rows == 1
    assert history == 1


class TestDetails:
    def test_set_details(self, db_session):
        from app.services.ingestion import set_listing_details

        listing = ingest_listing(
            db_session, raw_listing(raw_brand=None, raw_size=None), source="telegram", now=NOW
        ).listing
        result = set_listing_details(
            db_session, listing.id, now=NOW, raw_brand="  Stone   Island ", raw_size="",
            description="  Worn twice.  ",
        )  # fmt: skip
        assert result.content_changed
        assert (listing.raw_brand, listing.raw_size, listing.description) == (
            "Stone Island",
            None,
            "Worn twice.",
        )
        assert not set_listing_details(
            db_session, listing.id, now=NOW, raw_brand=None
        ).content_changed

    def test_errors(self, db_session):
        from app.services.ingestion import set_listing_details

        listing = ingest_listing(db_session, raw_listing(), source="telegram", now=NOW).listing
        with pytest.raises(ValueError, match="not editable"):
            set_listing_details(db_session, listing.id, now=NOW, price="1")
        with pytest.raises(NotFoundError):
            set_listing_details(db_session, 999999999, now=NOW, raw_size="L")
        with pytest.raises(ValidationFailedError, match="brand is too long"):
            set_listing_details(db_session, listing.id, now=NOW, raw_brand="x" * 101)
