"""Parse a free-text submission ("<vinted link> £45 L very good") into listing fields.

Only the unambiguous parts are extracted here: the item link (→ marketplace ID and a title
from the URL slug) and a price written with a currency marker. Everything else the operator
typed is kept as notes for the identification step (brand, size, condition, colour).
"""

from __future__ import annotations

import re
from decimal import Decimal

from pydantic import BaseModel, ConfigDict

from app.collectors.vinted.mapping import MARKETPLACE as VINTED
from app.collectors.vinted.mapping import find_item_url
from app.core.money import parse_price

_PRICE_TOKEN_RE = re.compile(
    r"(?<![\w.,])(?:£|€|\$|\b(?:gbp|eur|usd)\s?)\d[\d,]*(?:\.\d{1,2})?"
    r"|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:£|€|gbp|eur|usd|quid)\b",
    re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")
_SHARE_BOILERPLATE_RE = re.compile(
    r"\b(check out|look at|found) (this|these)\b.*?\bon vinted\b[:!.]?", re.IGNORECASE
)


class ParsedSubmission(BaseModel):
    model_config = ConfigDict(frozen=True)

    marketplace: str
    external_id: str | None
    url: str | None
    slug_title: str | None
    price: Decimal | None
    currency: str | None
    default_currency: str | None
    notes: str

    @property
    def title(self) -> str | None:
        """Best available title: the URL slug, else the operator's text."""
        return self.slug_title or (self.notes[:300] if self.notes else None)


def parse_submission_text(text: str, *, default_marketplace: str = VINTED) -> ParsedSubmission:
    remaining = text.strip()
    marketplace = default_marketplace
    external_id = url = slug_title = default_currency = None

    found = find_item_url(remaining)
    if found is not None:
        raw_url, ref = found
        marketplace = VINTED
        external_id = ref.external_id
        url = ref.canonical_url
        slug_title = ref.slug_title
        default_currency = ref.default_currency
        remaining = remaining.replace(raw_url, " ")

    price = currency = None
    parsed = parse_price(remaining)
    if parsed is not None:
        price, currency = parsed
        remaining = _PRICE_TOKEN_RE.sub(" ", remaining, count=1)

    remaining = _SHARE_BOILERPLATE_RE.sub(" ", remaining)
    notes = _WS_RE.sub(" ", remaining).strip(" -–|,;:")
    return ParsedSubmission(
        marketplace=marketplace,
        external_id=external_id,
        url=url,
        slug_title=slug_title,
        price=price,
        currency=currency,
        default_currency=default_currency,
        notes=notes,
    )
