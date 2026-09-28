"""Money helpers.

Rules (see docs/financial-calculations.md):

* Money is always :class:`~decimal.Decimal`, never ``float``. Passing a float raises ``TypeError``
  so that binary floating point can never leak into a price.
* Internal calculations keep full precision. Values are rounded half-up to 2 dp only at output
  boundaries (API responses, messages, persisted money columns).
* A maximum purchase price is always rounded *down* (see :func:`round_down_money`).
"""

from __future__ import annotations

import re
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation

PENNY = Decimal("0.01")
ZERO = Decimal("0")
ONE = Decimal("1")

_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_SYMBOLS: dict[str, str] = {"GBP": "£", "EUR": "€", "USD": "$"}
_SYMBOL_TO_CODE: dict[str, str] = {v: k for k, v in _SYMBOLS.items()}


def to_decimal(value: Decimal | int | str) -> Decimal:
    """Convert ``value`` to Decimal, refusing floats and non-finite values."""
    if isinstance(value, bool):
        raise TypeError("bool is not a money amount")
    if isinstance(value, float):
        raise TypeError("float is not allowed for money; pass a str or Decimal")
    if isinstance(value, Decimal):
        result = value
    elif isinstance(value, int):
        result = Decimal(value)
    elif isinstance(value, str):
        try:
            result = Decimal(value.strip())
        except InvalidOperation as exc:
            raise ValueError(f"not a decimal amount: {value!r}") from exc
    else:
        raise TypeError(f"unsupported money type: {type(value).__name__}")
    if not result.is_finite():
        raise ValueError("money amount must be finite")
    return result


def round_money(value: Decimal) -> Decimal:
    """Round half-up to whole pennies (the output-boundary rule)."""
    return value.quantize(PENNY, rounding=ROUND_HALF_UP)


def round_down_money(value: Decimal) -> Decimal:
    """Round towards negative infinity to whole pennies (used for maximum purchase prices)."""
    return value.quantize(PENNY, rounding=ROUND_FLOOR)


def is_valid_currency(code: str) -> bool:
    return bool(_CURRENCY_RE.match(code))


def normalise_currency(code: str) -> str:
    """Upper-case and validate an ISO-4217 style code (``"gbp"`` → ``"GBP"``)."""
    candidate = code.strip().upper()
    if candidate in _SYMBOL_TO_CODE:
        candidate = _SYMBOL_TO_CODE[candidate]
    if not is_valid_currency(candidate):
        raise ValueError(f"invalid currency code: {code!r}")
    return candidate


def currency_symbol(code: str) -> str | None:
    return _SYMBOLS.get(code)


def format_money(value: Decimal, currency: str) -> str:
    """Format for display, e.g. ``£1,234.50`` or ``1,234.50 CHF``."""
    rounded = round_money(value)
    sign = "-" if rounded < 0 else ""
    body = f"{abs(rounded):,.2f}"
    symbol = currency_symbol(currency)
    if symbol:
        return f"{sign}{symbol}{body}"
    return f"{sign}{body} {currency}"


def format_money_short(value: Decimal, currency: str) -> str:
    """Like :func:`format_money` but drops ``.00`` for whole amounts (``£110``)."""
    rounded = round_money(value)
    if rounded == rounded.to_integral_value():
        sign = "-" if rounded < 0 else ""
        body = f"{abs(rounded):,.0f}"
        symbol = currency_symbol(currency)
        return f"{sign}{symbol}{body}" if symbol else f"{sign}{body} {currency}"
    return format_money(value, currency)


def format_percent(value: Decimal, places: int = 0) -> str:
    """Format a ratio (``0.76`` → ``76%``)."""
    quant = Decimal(1).scaleb(-places)
    pct = (value * 100).quantize(quant, rounding=ROUND_HALF_UP)
    return f"{pct}%"


_PRICE_RE = re.compile(
    r"""
    (?<![\w.,])                                     # not inside another number/word
    (?P<pre>£|€|\$|\b(?:gbp|eur|usd)\s?)?           # optional leading symbol or code
    (?P<amount>\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?     # 1,234.50
              |\d{1,6}(?:[.,]\d{1,2})?)             # 45 / 45.5 / 45,50
    (?![\d])
    (?P<post>\s?(?:gbp|eur|usd|quid)\b|\s?[£€])?    # optional trailing code/symbol
    """,
    re.IGNORECASE | re.VERBOSE,
)
_THOUSANDS_RE = re.compile(r"^\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?$")


def _parse_amount(raw: str) -> Decimal:
    if _THOUSANDS_RE.match(raw):
        return Decimal(raw.replace(",", ""))
    return Decimal(raw.replace(",", "."))


def parse_price(text: str, *, require_marker: bool = True) -> tuple[Decimal, str | None] | None:
    """Find the first price in free text.

    Returns ``(amount, currency_or_None)``. With ``require_marker`` (the default) only amounts
    written with a currency symbol or code are accepted, so sizes such as ``48`` or
    ``UK 40`` are not mistaken for prices.
    """
    for match in _PRICE_RE.finditer(text):
        pre = (match.group("pre") or "").strip().lower()
        post = (match.group("post") or "").strip().lower()
        if require_marker and not pre and not post:
            continue
        marker = pre or post
        currency: str | None
        if marker in {"£", "gbp", "quid"}:
            currency = "GBP"
        elif marker in {"€", "eur"}:
            currency = "EUR"
        elif marker in {"$", "usd"}:
            currency = "USD"
        else:
            currency = None
        amount = _parse_amount(match.group("amount"))
        if amount <= 0:
            continue
        return amount, currency
    return None
