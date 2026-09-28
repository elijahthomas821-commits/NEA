"""Vinted field formats → marketplace-neutral values. Pure functions, no network access."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.analysis.normalisation.text import normalise_text
from app.core.enums import Condition

MARKETPLACE = "vinted"

_HOST_RE = re.compile(r"^(?:www\.)?vinted\.[a-z.]{2,10}$")
_ITEM_PATH_RE = re.compile(
    r"^/(?:[a-z]{2}(?:-[a-z]{2})?/)?items/(?P<id>\d{3,15})(?:-(?P<slug>[a-z0-9-]+))?/?$"
)
_MEMBER_PATH_RE = re.compile(r"^/(?:[a-z]{2}/)?member/(?P<id>\d{1,15})(?:-(?P<name>[^/]+))?/?$")
_URL_IN_TEXT_RE = re.compile(r"https?://(?:www\.)?vinted\.[a-z.]{2,10}/[^\s<>\"']+", re.IGNORECASE)

# Currency by site; used only as a default when the operator does not state one.
_SITE_CURRENCY = {
    "vinted.co.uk": "GBP",
    "vinted.fr": "EUR",
    "vinted.de": "EUR",
    "vinted.it": "EUR",
    "vinted.es": "EUR",
    "vinted.nl": "EUR",
    "vinted.be": "EUR",
    "vinted.at": "EUR",
    "vinted.ie": "EUR",
    "vinted.lu": "EUR",
    "vinted.pt": "EUR",
    "vinted.pl": "PLN",
    "vinted.cz": "CZK",
    "vinted.lt": "EUR",
    "vinted.se": "SEK",
    "vinted.dk": "DKK",
    "vinted.com": "USD",
}


@dataclass(frozen=True)
class VintedItemRef:
    external_id: str
    slug: str | None
    site: str

    @property
    def canonical_url(self) -> str:
        return f"https://www.{self.site}/items/{self.external_id}"

    @property
    def slug_title(self) -> str | None:
        """The URL slug as words ("stone-island-crewneck" → "stone island crewneck")."""
        if not self.slug:
            return None
        return self.slug.replace("-", " ").strip() or None

    @property
    def default_currency(self) -> str | None:
        return _SITE_CURRENCY.get(self.site)


def _site(host: str) -> str | None:
    host = host.lower().strip(".")
    if not _HOST_RE.match(host):
        return None
    return host.removeprefix("www.")


def parse_item_url(url: str) -> VintedItemRef | None:
    """Parse an item URL; returns None for anything that is not a Vinted item link."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    site = _site(parts.hostname)
    if site is None:
        return None
    match = _ITEM_PATH_RE.match(parts.path.lower())
    if match is None:
        return None
    return VintedItemRef(external_id=match.group("id"), slug=match.group("slug"), site=site)


def parse_member_url(url: str) -> tuple[str, str | None] | None:
    """``https://www.vinted.co.uk/member/123-name`` → ``("123", "name")``."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if not parts.hostname or _site(parts.hostname) is None:
        return None
    match = _MEMBER_PATH_RE.match(parts.path)
    if match is None:
        return None
    return match.group("id"), match.group("name")


def find_item_url(text: str) -> tuple[str, VintedItemRef] | None:
    """First Vinted item link in free text (e.g. a message shared from the Vinted app)."""
    for match in _URL_IN_TEXT_RE.findall(text):
        candidate = match.rstrip(".,);!?")
        ref = parse_item_url(candidate)
        if ref is not None:
            return candidate, ref
    return None


# Condition labels as shown on Vinted sites (English, French, German, Italian, Spanish, Dutch).
_CONDITION_LABELS: dict[str, Condition] = {}
for _condition, _labels in {
    Condition.NEW_WITH_TAGS: [
        "new with tags", "neuf avec etiquette", "neu mit etikett", "nuovo con cartellino",
        "nuevo con etiquetas", "nieuw met prijskaartje",
    ],
    Condition.NEW_WITHOUT_TAGS: [
        "new without tags", "neuf sans etiquette", "neu ohne etikett", "nuovo senza cartellino",
        "nuevo sin etiquetas", "nieuw zonder prijskaartje",
    ],
    Condition.VERY_GOOD: [
        "very good", "tres bon etat", "sehr gut", "ottime condizioni", "muy bueno", "zeer goed",
    ],
    Condition.GOOD: ["good", "bon etat", "gut", "buone condizioni", "bueno", "goed"],
    Condition.SATISFACTORY: [
        "satisfactory", "satisfaisant", "zufriedenstellend", "discrete condizioni",
        "satisfactorio", "redelijk",
    ],
}.items():  # fmt: skip
    for _label in _labels:
        _CONDITION_LABELS[normalise_text(_label)] = _condition


def map_condition_label(label: str | None) -> Condition | None:
    """Exact Vinted condition label → :class:`Condition` (free text is handled elsewhere)."""
    if not label:
        return None
    return _CONDITION_LABELS.get(normalise_text(label))


_LETTER_SIZES = {"XXS", "XS", "S", "M", "L", "XL", "XXL", "XXXL", "2XL", "3XL", "4XL"}


def clean_size_label(label: str | None) -> str | None:
    """Vinted shows composite labels such as ``"L / 40 / 12"``; keep the letter size if present."""
    if not label:
        return None
    parts = [p.strip() for p in re.split(r"[/|]", label) if p.strip()]
    for part in parts:
        if part.upper() in _LETTER_SIZES:
            return part.upper()
    return label.strip()
