"""Listing ingestion: validate → upsert seller → upsert listing → price/status history.

Duplicate safety: the ``UNIQUE (marketplace, external_id)`` constraint is the guard. New rows
are written with ``INSERT ... ON CONFLICT DO NOTHING``; when two submissions of the same listing
race, PostgreSQL makes the second wait for the first, which then updates the existing row
instead of inserting a copy.

Re-submitting a listing never erases data: fields missing from the new submission keep their
stored values.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.analysis.normalisation.text import normalise_text
from app.collectors.base import RawListing, RawSeller
from app.core.enums import ListingStatus
from app.core.errors import InvalidStateError, NotFoundError, ValidationFailedError
from app.models import Listing, ListingStatusHistory, Marketplace, PriceHistory, Seller

CONTENT_FIELDS = (
    "url",
    "title",
    "description",
    "raw_brand",
    "raw_category",
    "raw_size",
    "raw_colour",
    "raw_condition",
    "listed_at",
)
DUPLICATE_LOOKBACK = timedelta(days=30)
LIVE_STATUSES = (ListingStatus.ACTIVE.value, ListingStatus.RESERVED.value)


@dataclass
class IngestResult:
    listing: Listing
    created: bool
    price_changed: bool = False
    status_changed: bool = False
    content_changed: bool = False

    @property
    def needs_evaluation(self) -> bool:
        if self.listing.status not in LIVE_STATUSES:
            return False
        return self.created or self.price_changed or self.content_changed or self.status_changed


def compute_content_hash(fields: dict[str, Any], operator_notes: str | None) -> str:
    """Hash of the descriptive fields; a change means the listing needs re-identifying."""
    payload = {
        name: (value.isoformat() if isinstance(value, datetime) else value)
        for name in CONTENT_FIELDS
        if (value := fields.get(name)) is not None
    }
    if operator_notes:
        payload["operator_notes"] = operator_notes
    canonical = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _listing_hash(listing: Listing) -> str:
    fields = {name: getattr(listing, name) for name in CONTENT_FIELDS}
    return compute_content_hash(fields, (listing.raw_payload or {}).get("operator_notes"))


def _status(raw: RawListing) -> ListingStatus:
    if raw.status is None:
        return ListingStatus.ACTIVE
    try:
        return ListingStatus(raw.status)
    except ValueError as exc:
        raise ValidationFailedError(f"unknown listing status {raw.status!r}") from exc


def upsert_seller(session: Session, marketplace: str, seller: RawSeller, now: datetime) -> Seller:
    stmt = (
        pg_insert(Seller)
        .values(
            marketplace=marketplace,
            external_seller_id=seller.external_seller_id,
            username=seller.username,
            rating=seller.rating,
            review_count=seller.review_count,
            country=seller.country,
            member_since=seller.member_since,
            first_seen_at=now,
            last_seen_at=now,
        )
        .on_conflict_do_nothing(index_elements=["marketplace", "external_seller_id"])
        .returning(Seller.id)
    )
    new_id = session.execute(stmt).scalar_one_or_none()
    if new_id is not None:
        created = session.get(Seller, new_id)
        assert created is not None
        return created
    existing = session.execute(
        select(Seller)
        .where(
            Seller.marketplace == marketplace,
            Seller.external_seller_id == seller.external_seller_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    existing.last_seen_at = now
    for field in ("username", "rating", "review_count", "country", "member_since"):
        value = getattr(seller, field)
        if value is not None:
            setattr(existing, field, value)
    return existing


def ingest_listing(
    session: Session,
    raw: RawListing,
    *,
    source: str,
    now: datetime,
    user_id: int | None = None,
) -> IngestResult:
    """Create or update a listing from a :class:`RawListing`. Flushes; the caller commits."""
    if session.get(Marketplace, raw.marketplace) is None:
        raise ValidationFailedError(f"unknown marketplace {raw.marketplace!r}")
    status = _status(raw)
    seller_id = upsert_seller(session, raw.marketplace, raw.seller, now).id if raw.seller else None
    notes = raw.extra.get("operator_notes") or None
    raw_payload: dict[str, Any] = {"latest": raw.model_dump(mode="json", exclude_none=True)}
    if notes:
        raw_payload["operator_notes"] = notes

    fields = {name: getattr(raw, name) for name in CONTENT_FIELDS}
    stmt = (
        pg_insert(Listing)
        .values(
            marketplace=raw.marketplace,
            external_id=raw.external_id,
            seller_id=seller_id,
            source=source,
            price=raw.price,
            currency=raw.currency,
            first_seen_at=now,
            last_seen_at=now,
            status=status.value,
            status_changed_at=now,
            content_hash=compute_content_hash(fields, notes),
            raw_payload=raw_payload,
            submitted_by_user_id=user_id,
            **fields,
        )
        .on_conflict_do_nothing(index_elements=["marketplace", "external_id"])
        .returning(Listing.id)
    )
    new_id = session.execute(stmt).scalar_one_or_none()

    if new_id is not None:
        listing = session.get(Listing, new_id)
        assert listing is not None
        if listing.price is not None and listing.currency is not None:
            session.add(
                PriceHistory(
                    listing_id=listing.id,
                    price=listing.price,
                    currency=listing.currency,
                    previous_price=None,
                    observed_at=now,
                )
            )
        session.add(
            ListingStatusHistory(
                listing_id=listing.id, from_status=None, to_status=status.value, observed_at=now
            )
        )
        listing.possible_duplicate_of = find_possible_duplicate(session, listing, now)
        session.flush()
        return IngestResult(listing=listing, created=True)

    listing = session.execute(
        select(Listing)
        .where(Listing.marketplace == raw.marketplace, Listing.external_id == raw.external_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    result = IngestResult(listing=listing, created=False)
    listing.last_seen_at = now
    if seller_id is not None:
        listing.seller_id = seller_id
    for name, value in fields.items():
        if value is not None and getattr(listing, name) != value:
            setattr(listing, name, value)
    merged = dict(listing.raw_payload or {})
    merged["latest"] = raw_payload["latest"]
    if notes:
        merged["operator_notes"] = notes
    listing.raw_payload = merged

    if raw.price is not None:
        assert raw.currency is not None  # enforced by RawListing
        result.price_changed = _apply_price(session, listing, raw.price, raw.currency, now)
    if raw.status is not None:
        result.status_changed = _apply_status(session, listing, status, now, note=None)

    new_hash = _listing_hash(listing)
    if new_hash != listing.content_hash:
        listing.content_hash = new_hash
        result.content_changed = True
    session.flush()
    return result


def _apply_price(
    session: Session, listing: Listing, price: Decimal, currency: str, now: datetime
) -> bool:
    if price <= 0:
        raise ValidationFailedError("price must be positive")
    if listing.price == price and listing.currency == currency:
        return False
    session.add(
        PriceHistory(
            listing_id=listing.id,
            price=price,
            currency=currency,
            previous_price=listing.price if listing.currency == currency else None,
            observed_at=now,
        )
    )
    listing.price = price
    listing.currency = currency
    return True


def _apply_status(
    session: Session, listing: Listing, status: ListingStatus, now: datetime, *, note: str | None
) -> bool:
    if listing.status == status.value:
        return False
    session.add(
        ListingStatusHistory(
            listing_id=listing.id,
            from_status=listing.status,
            to_status=status.value,
            observed_at=now,
            note=note,
        )
    )
    listing.status = status.value
    listing.status_changed_at = now
    return True


def update_listing(
    session: Session,
    listing_id: int,
    *,
    now: datetime,
    price: Decimal | None = None,
    currency: str | None = None,
    status: ListingStatus | None = None,
    note: str | None = None,
) -> IngestResult:
    """Manual price/status update (e.g. "price dropped to £40", "it sold")."""
    listing = session.execute(
        select(Listing)
        .where(Listing.id == listing_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if listing is None:
        raise NotFoundError(f"listing {listing_id} not found")
    result = IngestResult(listing=listing, created=False)
    if price is not None:
        effective_currency = currency or listing.currency
        if effective_currency is None:
            raise ValidationFailedError("currency is required with a price")
        result.price_changed = _apply_price(session, listing, price, effective_currency, now)
    if status is not None:
        if listing.status == ListingStatus.REMOVED.value and status == ListingStatus.SOLD:
            raise InvalidStateError("a removed listing cannot be marked sold")
        result.status_changed = _apply_status(session, listing, status, now, note=note)
    listing.last_seen_at = now
    session.flush()
    return result


def find_possible_duplicate(session: Session, listing: Listing, now: datetime) -> int | None:
    """The same item re-listed under a new ID: same seller (or same price) and same title."""
    title_norm = normalise_text(listing.title)
    if not title_norm:
        return None
    query = select(Listing).where(
        Listing.id != listing.id,
        Listing.marketplace == listing.marketplace,
        Listing.first_seen_at >= now - DUPLICATE_LOOKBACK,
    )
    if listing.seller_id is not None:
        query = query.where(Listing.seller_id == listing.seller_id)
    elif listing.price is not None:
        query = query.where(Listing.price == listing.price)
    else:
        return None
    for candidate in session.scalars(query.order_by(Listing.first_seen_at.desc()).limit(50)):
        if normalise_text(candidate.title) == title_norm:
            return candidate.id
    return None
