"""Listing submission and management."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, Query, Request, Response, UploadFile
from sqlalchemy import func, select

from app.api.deps import DispatcherDep, PrincipalDep, SessionDep, SettingsDep
from app.api.uploads import read_upload
from app.core.enums import ListingStatus
from app.core.errors import NotFoundError
from app.core.time import utcnow
from app.models import Listing, ListingImage, PriceHistory
from app.schemas.listings import (
    ImageOut,
    ListingIngestOut,
    ListingOut,
    ListingSubmission,
    ListingUpdate,
    QuickSubmission,
)
from app.services.images import add_listing_image
from app.services.ingestion import IngestResult, ingest_listing, update_listing
from app.services.submissions import (
    missing_fields,
    raw_listing_from_submission,
    raw_listing_from_text,
)
from app.workers.dispatch import TaskDispatcher

router = APIRouter(prefix="/listings", tags=["listings"])


def _trigger_for(result: IngestResult) -> str:
    if result.created:
        return "ingest"
    if result.price_changed:
        return "price_change"
    return "manual"


def _queue_if_needed(
    request: Request, dispatcher: TaskDispatcher, result: IngestResult, notify: bool
) -> bool:
    if not result.needs_evaluation:
        return False
    dispatcher.evaluate_listing(
        result.listing.id,
        trigger=_trigger_for(result),
        notify=notify,
        correlation_id=getattr(request.state, "correlation_id", None),
    )
    return True


@router.post("", response_model=ListingIngestOut)
def submit_listing(
    body: ListingSubmission,
    request: Request,
    response: Response,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: DispatcherDep,
) -> ListingIngestOut:
    """Submit a listing you found. It is stored (or updated) and queued for evaluation."""
    raw = raw_listing_from_submission(body, base_currency=settings.base_currency)
    result = ingest_listing(session, raw, source="api", now=utcnow(), user_id=principal.user.id)
    session.commit()
    queued = _queue_if_needed(request, dispatcher, result, body.notify)
    response.status_code = 201 if result.created else 200
    return ListingIngestOut(
        listing=ListingOut.model_validate(result.listing),
        created=result.created,
        evaluation_queued=queued,
        missing_fields=missing_fields(raw),
    )


@router.post("/quick", response_model=ListingIngestOut)
def submit_quick(
    body: QuickSubmission,
    request: Request,
    response: Response,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: DispatcherDep,
) -> ListingIngestOut:
    """Submit free text: a Vinted link plus anything you know (price, size, condition)."""
    raw, _ = raw_listing_from_text(
        body.text,
        base_currency=settings.base_currency,
        default_marketplace=settings.default_marketplace,
    )
    result = ingest_listing(session, raw, source="api", now=utcnow(), user_id=principal.user.id)
    session.commit()
    queued = _queue_if_needed(request, dispatcher, result, body.notify)
    response.status_code = 201 if result.created else 200
    return ListingIngestOut(
        listing=ListingOut.model_validate(result.listing),
        created=result.created,
        evaluation_queued=queued,
        missing_fields=missing_fields(raw),
    )


@router.get("")
def list_listings(
    principal: PrincipalDep,
    session: SessionDep,
    status: ListingStatus | None = None,
    brand_id: int | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    query = select(Listing)
    if status is not None:
        query = query.where(Listing.status == status.value)
    if brand_id is not None:
        query = query.where(Listing.brand_id == brand_id)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(Listing.title.ilike(f"%{escaped}%", escape="\\"))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(
        query.order_by(Listing.first_seen_at.desc(), Listing.id.desc()).limit(limit).offset(offset)
    )
    return {
        "items": [ListingOut.model_validate(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def _get_listing(session: SessionDep, listing_id: int) -> Listing:
    listing = session.get(Listing, listing_id)
    if listing is None:
        raise NotFoundError(f"listing {listing_id} not found")
    return listing


@router.get("/{listing_id}", response_model=ListingOut)
def get_listing(listing_id: int, principal: PrincipalDep, session: SessionDep) -> ListingOut:
    return ListingOut.model_validate(_get_listing(session, listing_id))


@router.patch("/{listing_id}", response_model=ListingIngestOut)
def patch_listing(
    listing_id: int,
    body: ListingUpdate,
    request: Request,
    principal: PrincipalDep,
    session: SessionDep,
    dispatcher: DispatcherDep,
) -> ListingIngestOut:
    """Record a price change or a status change (reserved, sold, removed)."""
    result = update_listing(
        session,
        listing_id,
        now=utcnow(),
        price=body.price,
        currency=body.currency,
        status=body.status,
        note=body.note,
    )
    session.commit()
    queued = (
        _queue_if_needed(request, dispatcher, result, notify=True) if body.reevaluate else False
    )
    return ListingIngestOut(
        listing=ListingOut.model_validate(result.listing), created=False, evaluation_queued=queued
    )


@router.get("/{listing_id}/price-history")
def price_history(
    listing_id: int, principal: PrincipalDep, session: SessionDep
) -> list[dict[str, Any]]:
    _get_listing(session, listing_id)
    rows = session.scalars(
        select(PriceHistory)
        .where(PriceHistory.listing_id == listing_id)
        .order_by(PriceHistory.observed_at)
    )
    return [
        {
            "price": row.price,
            "currency": row.currency,
            "previous_price": row.previous_price,
            "observed_at": row.observed_at,
        }
        for row in rows
    ]


@router.post("/{listing_id}/images", response_model=list[ImageOut])
def upload_images(
    listing_id: int,
    request: Request,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: DispatcherDep,
    files: Annotated[list[UploadFile], File(description="JPEG, PNG or WebP photos")],
) -> list[ImageOut]:
    """Upload listing photos (labels, badges, tags help the authenticity check)."""
    listing = _get_listing(session, listing_id)
    out: list[ImageOut] = []
    any_created = False
    for upload in files:
        data = read_upload(upload, settings.max_image_bytes)
        stored = add_listing_image(
            session,
            listing,
            data,
            media_dir=settings.media_dir,
            max_bytes=settings.max_image_bytes,
            max_images=settings.max_images_per_listing,
        )
        any_created |= stored.created
        item = ImageOut.model_validate(stored.image)
        item.created = stored.created
        out.append(item)
    session.commit()
    if any_created and listing.status in (ListingStatus.ACTIVE.value, ListingStatus.RESERVED.value):
        dispatcher.evaluate_listing(
            listing.id,
            trigger="manual",
            notify=True,
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    return out


@router.get("/{listing_id}/images", response_model=list[ImageOut])
def list_images(listing_id: int, principal: PrincipalDep, session: SessionDep) -> list[ImageOut]:
    _get_listing(session, listing_id)
    rows = session.scalars(
        select(ListingImage)
        .where(ListingImage.listing_id == listing_id)
        .order_by(ListingImage.position)
    )
    return [ImageOut.model_validate(row) for row in rows]
