"""Parsing what the operator types to the bot (commands, amounts, one-line comps)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from decimal import Decimal

from app.core.errors import ValidationFailedError
from app.core.money import parse_price

_COMMAND_RE = re.compile(r"^/(?P<name>[A-Za-z0-9_]{1,32})(?:@\w+)?(?:\s+(?P<args>.*))?$", re.S)
_AMOUNT_RE = re.compile(r"(?<![\w.,])(?:£|€|\$)?\s?(\d{1,6}(?:[.,]\d{1,2})?)(?![\d])")
_REF_RE = re.compile(r"^#?(\d{1,12})$")
MAX_AMOUNT = Decimal("100000")

COMP_FORMAT = (
    "brand | category | price | size | condition | sold date\n"
    "(size, condition and date are optional)"
)
COMP_EXAMPLE = "Stone Island | sweatshirts | £95 | L | very good | 2026-09-20"


def parse_command(text: str) -> tuple[str, str] | None:
    match = _COMMAND_RE.match(text.strip())
    if match is None:
        return None
    return match.group("name").lower(), (match.group("args") or "").strip()


def parse_amount(text: str) -> tuple[Decimal, str | None] | None:
    """A single money amount; a bare number counts (``45``, ``£45.50``, ``45,50``)."""
    found = parse_price(text, require_marker=False)
    if found is None or found[0] <= 0 or found[0] > MAX_AMOUNT:
        return None
    return found


def parse_amounts(text: str) -> list[Decimal]:
    """Every amount in the text, in order (``"2.95 3.49"`` → two amounts)."""
    out = []
    for match in _AMOUNT_RE.finditer(text):
        value = Decimal(match.group(1).replace(",", "."))
        if value > MAX_AMOUNT:
            raise ValidationFailedError("that amount looks too large")
        out.append(value)
    return out


def parse_listing_ref(text: str) -> int | None:
    match = _REF_RE.match(text.strip())
    return int(match.group(1)) if match else None


@dataclass(frozen=True)
class CompInput:
    brand: str
    category: str
    price: Decimal
    currency: str | None
    size: str | None
    condition: str | None
    sold_at: datetime


def parse_comp(text: str, *, now: datetime) -> CompInput:
    parts = [p.strip() for p in text.split("|")]
    if len(parts) < 3 or not all(parts[:3]):
        raise ValidationFailedError(
            f"Send the sale as:\n{COMP_FORMAT}\nFor example: {COMP_EXAMPLE}"
        )
    if len(parts) > 6:
        raise ValidationFailedError(f"Too many parts. Use:\n{COMP_FORMAT}")
    amount = parse_amount(parts[2])
    if amount is None:
        raise ValidationFailedError(f"{parts[2]!r} is not a price")
    size = parts[3] if len(parts) > 3 and parts[3] else None
    condition = parts[4] if len(parts) > 4 and parts[4] else None
    sold_at = now
    if len(parts) > 5 and parts[5]:
        try:
            sold_day = date.fromisoformat(parts[5])
        except ValueError:
            raise ValidationFailedError("the sold date must look like 2026-09-20") from None
        if sold_day > now.date():
            raise ValidationFailedError("the sold date is in the future")
        sold_at = min(datetime.combine(sold_day, time(12), tzinfo=UTC), now)
    for label, value, limit in (("brand", parts[0], 100), ("category", parts[1], 100)):
        if len(value) > limit:
            raise ValidationFailedError(f"the {label} is too long")
    return CompInput(
        brand=parts[0],
        category=parts[1],
        price=amount[0],
        currency=amount[1],
        size=size[:50] if size else None,
        condition=condition[:50] if condition else None,
        sold_at=sold_at,
    )
