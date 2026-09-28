"""CSV imports with a row-level validation report.

Each row is processed in its own SAVEPOINT, so one bad row never aborts the rest; the run
records how many rows were created, updated, skipped or failed, with the errors per row.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.errors import AppError, ValidationFailedError
from app.core.redaction import safe_error_summary
from app.models import IngestionRun
from app.schemas.listings import ListingSubmission
from app.services.ingestion import IngestResult, ingest_listing
from app.services.submissions import raw_listing_from_submission

MAX_REPORTED_ERRORS = 200

LISTING_COLUMNS = [
    "marketplace",
    "external_id",
    "url",
    "title",
    "description",
    "brand",
    "category",
    "size",
    "colour",
    "condition",
    "price",
    "currency",
    "listed_at",
    "seller_id",
    "seller_username",
    "seller_rating",
    "seller_review_count",
    "notes",
]


def csv_template(columns: list[str]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer).writerow(columns)
    return buffer.getvalue()


def read_csv_rows(content: bytes, *, max_rows: int) -> tuple[list[str], list[dict[str, str]]]:
    """Decode and parse the whole file up front, so limits fail before any row is written."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationFailedError("CSV must be UTF-8 encoded") from exc
    reader = csv.DictReader(io.StringIO(text))
    header = [h.strip().lower() for h in (reader.fieldnames or [])]
    if not header:
        raise ValidationFailedError("CSV has no header row")
    reader.fieldnames = header
    rows: list[dict[str, str]] = []
    try:
        for row in reader:
            if len(rows) >= max_rows:
                raise ValidationFailedError(f"CSV has more than {max_rows} rows")
            rows.append({k: (v or "").strip() for k, v in row.items() if k is not None})
    except csv.Error as exc:
        raise ValidationFailedError(f"malformed CSV: {exc}") from exc
    return header, rows


def parse_decimal(value: str, field: str) -> Decimal | None:
    if not value:
        return None
    cleaned = value.replace("£", "").replace("€", "").replace("$", "").strip()
    try:
        return Decimal(cleaned)
    except InvalidOperation as exc:
        raise ValueError(f"{field}: not a number: {value!r}") from exc


def parse_datetime(value: str, field: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{field}: use ISO 8601 dates, e.g. 2026-09-01 or 2026-09-01T14:30"
        ) from exc


def _errors_from(exc: Exception) -> list[str]:
    if isinstance(exc, ValidationError):
        return [
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_url=False)
        ]
    if isinstance(exc, AppError):
        extra = exc.details.get("errors") if exc.details else None
        if extra:
            return [f"{e.get('loc', '')}: {e.get('msg', '')}" for e in extra]
        return [exc.message]
    if isinstance(exc, ValueError):
        return [str(exc)]
    return [safe_error_summary(exc)]


def run_import(
    session: Session,
    *,
    kind: str,
    source: str,
    content: bytes,
    now: datetime,
    user_id: int | None,
    max_rows: int,
    required_columns: set[str],
    handle_row: Callable[[dict[str, str]], str],
) -> IngestionRun:
    """Generic driver. ``handle_row`` returns "created", "updated" or "skipped"."""
    run = IngestionRun(kind=kind, source=source[:100], status="running", started_at=now, report={})
    run.created_by_user_id = user_id
    session.add(run)
    session.flush()
    errors: list[dict[str, Any]] = []
    counts = {"created": 0, "updated": 0, "skipped": 0, "failed": 0}
    total = 0
    try:
        header, rows = read_csv_rows(content, max_rows=max_rows)
        missing = required_columns - set(header)
        if missing:
            raise ValidationFailedError(f"CSV is missing columns: {', '.join(sorted(missing))}")
        for line_no, row in enumerate(rows, start=2):  # line 1 is the header
            total += 1
            savepoint = session.begin_nested()
            try:
                outcome = handle_row(row)
                savepoint.commit()
                counts[outcome] += 1
            except Exception as exc:
                savepoint.rollback()
                counts["failed"] += 1
                if len(errors) < MAX_REPORTED_ERRORS:
                    errors.append({"line": line_no, "errors": _errors_from(exc)})
    except ValidationFailedError as exc:
        run.status = "failed"
        run.error_summary = exc.message[:1000]
    else:
        if counts["failed"] == 0:
            run.status = "ok"
        elif counts["failed"] == total:
            run.status = "failed"
            run.error_summary = "every row failed validation"
        else:
            run.status = "partial"
    run.rows_total = total
    run.rows_created = counts["created"]
    run.rows_updated = counts["updated"]
    run.rows_skipped = counts["skipped"]
    run.rows_failed = counts["failed"]
    run.report = {"errors": errors, "errors_truncated": counts["failed"] > len(errors)}
    run.finished_at = now
    session.flush()
    return run


def import_listings_csv(
    session: Session,
    content: bytes,
    *,
    source: str,
    base_currency: str,
    now: datetime,
    user_id: int | None = None,
    max_rows: int = 5000,
) -> tuple[IngestionRun, list[IngestResult]]:
    results: list[IngestResult] = []

    def handle(row: dict[str, str]) -> str:
        seller = None
        if row.get("seller_id"):
            seller = {
                "external_seller_id": row["seller_id"],
                "username": row.get("seller_username") or None,
                "rating": parse_decimal(row.get("seller_rating", ""), "seller_rating"),
                "review_count": int(row["seller_review_count"])
                if row.get("seller_review_count")
                else None,
            }
        submission = ListingSubmission.model_validate(
            {
                "marketplace": row.get("marketplace") or "vinted",
                "url": row.get("url") or None,
                "external_id": row.get("external_id") or None,
                "title": row.get("title") or None,
                "description": row.get("description") or None,
                "brand": row.get("brand") or None,
                "category": row.get("category") or None,
                "size": row.get("size") or None,
                "colour": row.get("colour") or None,
                "condition": row.get("condition") or None,
                "price": parse_decimal(row.get("price", ""), "price"),
                "currency": row.get("currency") or None,
                "listed_at": parse_datetime(row.get("listed_at", ""), "listed_at"),
                "seller": seller,
                "notes": row.get("notes") or None,
            }
        )
        raw = raw_listing_from_submission(submission, base_currency=base_currency)
        result = ingest_listing(session, raw, source="csv", now=now, user_id=user_id)
        results.append(result)
        if result.created:
            return "created"
        changed = result.price_changed or result.status_changed or result.content_changed
        return "updated" if changed else "skipped"

    run = run_import(
        session,
        kind="listings_csv",
        source=source,
        content=content,
        now=now,
        user_id=user_id,
        max_rows=max_rows,
        required_columns={"title"},
        handle_row=handle,
    )
    return run, results
