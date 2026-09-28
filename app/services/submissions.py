"""Turning operator submissions (API JSON, free text, CSV rows) into :class:`RawListing`."""

from __future__ import annotations

from pydantic import ValidationError

from app.collectors.base import RawListing
from app.collectors.manual.parser import ParsedSubmission, parse_submission_text
from app.collectors.vinted.mapping import MARKETPLACE as VINTED
from app.collectors.vinted.mapping import clean_size_label, parse_item_url
from app.core.errors import ValidationFailedError
from app.core.ids import manual_external_id
from app.schemas.listings import ListingSubmission


def _validation_error(exc: ValidationError) -> ValidationFailedError:
    errors = [
        {"loc": ".".join(str(p) for p in err["loc"]), "msg": err["msg"]}
        for err in exc.errors(include_url=False)
    ]
    return ValidationFailedError("invalid listing", details={"errors": errors})


def raw_listing_from_submission(sub: ListingSubmission, *, base_currency: str) -> RawListing:
    url = str(sub.url) if sub.url else None
    external_id = sub.external_id
    title = sub.title
    default_currency: str | None = None
    marketplace = sub.marketplace

    if url:
        ref = parse_item_url(url)
        if ref is not None:
            marketplace = VINTED
            external_id = external_id or ref.external_id
            url = ref.canonical_url
            title = title or ref.slug_title
            default_currency = ref.default_currency
    if not title:
        raise ValidationFailedError(
            "a title is required (or a Vinted link whose address contains the title)"
        )
    currency = sub.currency or ((default_currency or base_currency) if sub.price else None)
    extra = {"operator_notes": sub.notes} if sub.notes else {}
    try:
        return RawListing(
            marketplace=marketplace,
            external_id=external_id or manual_external_id(),
            url=url,
            title=title,
            description=sub.description,
            raw_brand=sub.brand,
            raw_category=sub.category,
            raw_size=clean_size_label(sub.size) if marketplace == VINTED else sub.size,
            raw_colour=sub.colour,
            raw_condition=sub.condition,
            price=sub.price,
            currency=currency,
            listed_at=sub.listed_at,
            seller=sub.seller,
            extra=extra,
        )
    except ValidationError as exc:
        raise _validation_error(exc) from exc


def raw_listing_from_text(
    text: str, *, base_currency: str, default_marketplace: str = VINTED
) -> tuple[RawListing, ParsedSubmission]:
    """Quick add from free text. The operator's words beyond link/price become notes."""
    parsed = parse_submission_text(text, default_marketplace=default_marketplace)
    title = parsed.title
    if not title:
        raise ValidationFailedError("could not find a title: include the listing link or a title")
    currency = parsed.currency or (
        (parsed.default_currency or base_currency) if parsed.price is not None else None
    )
    notes = parsed.notes if parsed.slug_title else None
    try:
        raw = RawListing(
            marketplace=parsed.marketplace,
            external_id=parsed.external_id or manual_external_id(),
            url=parsed.url,
            title=title,
            price=parsed.price,
            currency=currency,
            extra={"operator_notes": notes} if notes else {},
        )
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    return raw, parsed


def missing_fields(raw: RawListing) -> list[str]:
    """Fields worth asking the operator for before an evaluation can be meaningful."""
    missing = []
    if raw.price is None:
        missing.append("price")
    return missing
