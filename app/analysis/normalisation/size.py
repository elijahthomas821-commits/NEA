"""Size normalisation to the letter scale XXS … 4XL.

Rules:

* Letter sizes in any common spelling ("Medium", "X-Large", "2XL") map directly.
* A number is only converted when its system is known: stated in the listing ("IT 48", "EU 50",
  "UK 40", "40 chest"), or the brand's default system from config (Moncler "3" → L,
  C.P. Company "50" → L). Otherwise the size is left unknown rather than guessed — "44" is XS
  in Italian sizing and XXL as a UK chest size.
* Children's sizes are flagged (``is_kids``); they are priced differently from adult sizes.
* In a seller's title, a bare letter is only read as a size when it is written in capitals
  ("... Navy L"), so "l" or "m" inside ordinary words or measurements is ignored.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.analysis.normalisation.text import tokenise
from app.config.schemas import LETTER_SCALE, SizesConfig

SizeSource = Literal["field", "notes", "title", "description"]

_LETTER_ALIASES: dict[str, str] = {
    "xxs": "XXS",
    "2xs": "XXS",
    "xs": "XS",
    "x small": "XS",
    "extra small": "XS",
    "s": "S",
    "sm": "S",
    "small": "S",
    "m": "M",
    "med": "M",
    "medium": "M",
    "l": "L",
    "lg": "L",
    "large": "L",
    "xl": "XL",
    "x large": "XL",
    "extra large": "XL",
    "xxl": "XXL",
    "2xl": "XXL",
    "xx large": "XXL",
    "xxxl": "3XL",
    "3xl": "3XL",
    "xxx large": "3XL",
    "xxxxl": "4XL",
    "4xl": "4XL",
}
_UPPER_LETTER_TOKEN = re.compile(
    r"(?<![\w/])(XXS|2XS|XS|S|M|L|XL|XXL|2XL|XXXL|3XL|XXXXL|4XL)(?![\w/])"
)
_SIZE_PREFIX = re.compile(
    r"\b(?:size|sz|taille|gr|grosse|taglia)\b[\s:.#-]*(?P<value>[a-z0-9][a-z0-9 .\-/]{0,14})",
    re.IGNORECASE,
)
_SYSTEM_NUMBER = re.compile(
    r"\b(?P<system>it|ita|eu|fr|uk|us)\s?(?P<number>\d{1,2})\b", re.IGNORECASE
)
_CHEST = re.compile(
    r"\b(?:chest\s?(?P<a>\d{2})|(?P<b>\d{2})\s?(?:\"|in\b|inch\b|inches\b|”)?\s?chest)\b",
    re.IGNORECASE,
)
_KIDS_TOKENS = {
    "kids", "kid", "kids'", "boys", "girls", "junior", "juniors", "youth", "child",
    "childs", "children", "childrens", "teen", "teens", "toddler", "baby",
}  # fmt: skip
# Free text: only unambiguous children's sizing ("age 12", "12-13 years", "12y"), so that
# "worn for 2 years" is not read as a child's size.
_KIDS_TEXT_PATTERNS = [
    re.compile(r"\bage\s?\d{1,2}\b", re.IGNORECASE),
    re.compile(r"\b\d{1,2}\s?(?:-|to)\s?\d{1,2}\s?(?:y|yr|yrs|years?)\b", re.IGNORECASE),
    re.compile(r"\b\d{1,2}y\b", re.IGNORECASE),
]
# A size field saying "12 years" can only mean a child's size.
_KIDS_FIELD_PATTERNS = [
    *_KIDS_TEXT_PATTERNS,
    re.compile(r"\b\d{1,2}\s?(?:yrs|years)\b", re.IGNORECASE),
]
_SYSTEM_BY_PREFIX = {
    "it": "eu_it",
    "ita": "eu_it",
    "eu": "eu_it",
    "fr": "eu_it",
    "uk": "uk_chest",
    "us": "uk_chest",
}


class SizeResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    normalised: str | None = None
    system: str | None = None
    raw: str | None = None
    source: SizeSource | None = None
    is_kids: bool = False
    ambiguous: bool = False

    @property
    def index(self) -> int | None:
        return LETTER_SCALE.index(self.normalised) if self.normalised in LETTER_SCALE else None

    @property
    def known(self) -> bool:
        return self.normalised is not None


UNKNOWN = SizeResult()


def size_distance(a: str | None, b: str | None) -> int | None:
    if a not in LETTER_SCALE or b not in LETTER_SCALE:
        return None
    return abs(LETTER_SCALE.index(a) - LETTER_SCALE.index(b))


def is_kids_text(text: str | None, *, field: bool = False) -> bool:
    if not text:
        return False
    tokens = set(tokenise(text))
    if tokens & _KIDS_TOKENS:
        return True
    patterns = _KIDS_FIELD_PATTERNS if field else _KIDS_TEXT_PATTERNS
    return any(p.search(text) for p in patterns)


def _from_number(
    number: str, system: str | None, brand_slug: str | None, config: SizesConfig
) -> tuple[str | None, str | None, bool]:
    """Returns (letter, system, ambiguous)."""
    if system is None:
        system = config.brand_numeric_system.get(brand_slug or "") or config.default_numeric_system
    if system is None:
        return None, None, True
    mapping = config.numeric_systems.get(system, {})
    letter = mapping.get(number) or mapping.get(number.lstrip("0") or "0")
    return (letter, system, letter is None)


def parse_size_value(
    value: str | None,
    *,
    brand_slug: str | None,
    config: SizesConfig,
    source: SizeSource = "field",
) -> SizeResult:
    """Interpret one size value (a field like "L", "IT 50", "3", "Age 12", "S/M")."""
    if not value or not value.strip():
        return UNKNOWN
    raw = value.strip()
    if is_kids_text(raw, field=True):
        return SizeResult(raw=raw, source=source, is_kids=True, system="kids")
    norm = " ".join(tokenise(raw.replace("-", " ")))
    if norm in {"one size", "os", "onesize", "one size fits all"}:
        return SizeResult(raw=raw, source=source, system="one_size")
    if norm in _LETTER_ALIASES:
        return SizeResult(normalised=_LETTER_ALIASES[norm], system="letter", raw=raw, source=source)
    # "S/M", "M-L": two sizes → ambiguous.
    parts = [p for p in re.split(r"\s*[/|]\s*|\s+to\s+", raw.lower()) if p]
    if len(parts) == 2 and all(" ".join(tokenise(p)) in _LETTER_ALIASES for p in parts):
        return SizeResult(raw=raw, source=source, ambiguous=True)
    match = _SYSTEM_NUMBER.fullmatch(raw.strip()) or _SYSTEM_NUMBER.search(raw)
    if match:
        system = _SYSTEM_BY_PREFIX[match.group("system").lower()]
        letter, system_used, ambiguous = _from_number(
            match.group("number"), system, brand_slug, config
        )
        return SizeResult(
            normalised=letter, system=system_used, raw=raw, source=source, ambiguous=ambiguous
        )
    chest = _CHEST.search(raw)
    if chest:
        number = chest.group("a") or chest.group("b")
        letter, system_used, ambiguous = _from_number(number, "uk_chest", brand_slug, config)
        return SizeResult(
            normalised=letter, system=system_used, raw=raw, source=source, ambiguous=ambiguous
        )
    if re.fullmatch(r"\d{1,2}", norm):
        letter, system_used, ambiguous = _from_number(norm, None, brand_slug, config)
        return SizeResult(
            normalised=letter, system=system_used, raw=raw, source=source, ambiguous=ambiguous
        )
    # Composite labels such as "L / 40 / 12": take the first letter size.
    for part in parts:
        candidate = " ".join(tokenise(part))
        if candidate in _LETTER_ALIASES:
            return SizeResult(
                normalised=_LETTER_ALIASES[candidate], system="letter", raw=raw, source=source
            )
    return SizeResult(raw=raw, source=source, ambiguous=True)


def find_size_in_text(
    text: str | None,
    *,
    brand_slug: str | None,
    config: SizesConfig,
    source: SizeSource,
    case_insensitive_letters: bool = False,
) -> SizeResult:
    """Find a size mentioned in free text (a title, a description or your notes)."""
    if not text:
        return UNKNOWN
    if is_kids_text(text):
        return SizeResult(raw=text[:50], source=source, is_kids=True, system="kids")
    prefixed = _SIZE_PREFIX.search(text)
    if prefixed:
        value = prefixed.group("value").strip()
        # Only the first word or two after "size" belong to it ("size L navy" → "L").
        words = value.split()
        for take in (2, 1):
            candidate = " ".join(words[:take])
            result = parse_size_value(
                candidate, brand_slug=brand_slug, config=config, source=source
            )
            if result.known or result.is_kids:
                return result
    for pattern in (_SYSTEM_NUMBER, _CHEST):
        found = pattern.search(text)
        if found:
            result = parse_size_value(
                found.group(0), brand_slug=brand_slug, config=config, source=source
            )
            if result.known:
                return result
    if case_insensitive_letters:
        for token in tokenise(text):
            if token in _LETTER_ALIASES and len(token) <= 5:
                return SizeResult(
                    normalised=_LETTER_ALIASES[token], system="letter", raw=token, source=source
                )
        for phrase in ("extra large", "x large", "xx large", "small", "medium", "large"):
            if f" {phrase} " in f" {' '.join(tokenise(text))} ":
                return SizeResult(
                    normalised=_LETTER_ALIASES[phrase], system="letter", raw=phrase, source=source
                )
    else:
        upper = _UPPER_LETTER_TOKEN.findall(text)
        if upper:
            letter = _LETTER_ALIASES[upper[-1].lower()]
            return SizeResult(normalised=letter, system="letter", raw=upper[-1], source=source)
    return UNKNOWN


def size_tokens(result: SizeResult) -> set[str]:
    """Tokens that expressed the size (removed from the text used for product matching)."""
    if result.raw is None:
        return set()
    return set(tokenise(result.raw))
