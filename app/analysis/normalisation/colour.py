"""Colour normalisation to a small canonical palette.

Brand words are never read as colours: "stone" is only a colour in a structured colour field,
because free text containing "Stone Island" would otherwise always read as beige.
"""

from __future__ import annotations

from app.analysis.normalisation.text import find_phrase, tokenise

CANONICAL_COLOURS = (
    "black",
    "white",
    "grey",
    "navy",
    "blue",
    "green",
    "khaki",
    "red",
    "burgundy",
    "orange",
    "yellow",
    "pink",
    "purple",
    "brown",
    "beige",
    "multi",
)

# phrase → canonical colour; field_only phrases are ignored in free text.
_SYNONYMS: dict[str, str] = {
    "black": "black",
    "jet black": "black",
    "white": "white",
    "off white": "beige",
    "grey": "grey",
    "gray": "grey",
    "charcoal": "grey",
    "heather grey": "grey",
    "light grey": "grey",
    "dark grey": "grey",
    "silver": "grey",
    "navy": "navy",
    "navy blue": "navy",
    "dark blue": "navy",
    "midnight blue": "navy",
    "blue": "blue",
    "light blue": "blue",
    "sky blue": "blue",
    "royal blue": "blue",
    "cobalt": "blue",
    "turquoise": "blue",
    "teal": "green",
    "green": "green",
    "forest green": "green",
    "bottle green": "green",
    "mint green": "green",
    "sage": "green",
    "olive": "khaki",
    "olive green": "khaki",
    "khaki": "khaki",
    "military green": "khaki",
    "army green": "khaki",
    "red": "red",
    "burgundy": "burgundy",
    "maroon": "burgundy",
    "wine": "burgundy",
    "bordeaux": "burgundy",
    "orange": "orange",
    "rust": "orange",
    "yellow": "yellow",
    "mustard": "yellow",
    "pink": "pink",
    "coral": "pink",
    "rose": "pink",
    "purple": "purple",
    "lilac": "purple",
    "lavender": "purple",
    "violet": "purple",
    "brown": "brown",
    "tan": "brown",
    "camel": "brown",
    "chocolate": "brown",
    "beige": "beige",
    "cream": "beige",
    "ecru": "beige",
    "sand": "beige",
    "multi": "multi",
    "multicolour": "multi",
    "multicolor": "multi",
    "multicoloured": "multi",
    "camo": "multi",
    "camouflage": "multi",
    "tie dye": "multi",
}
# Words that are colours in a colour selector but mean something else in free text
# ("Stone Island", "mint condition", "natural fibres").
_FIELD_ONLY: dict[str, str] = {
    "stone": "beige",
    "ice": "white",
    "mint": "green",
    "natural": "beige",
}
_BY_LENGTH = sorted(_SYNONYMS, key=lambda p: -len(p.split()))


def normalise_colour_field(value: str | None) -> str | None:
    """A structured colour field (e.g. Vinted's colour selector)."""
    if not value:
        return None
    tokens = tokenise(value)
    joined = " ".join(tokens)
    if joined in _FIELD_ONLY:
        return _FIELD_ONLY[joined]
    return find_colour(value)


def find_colour(text: str | None) -> str | None:
    """The first colour mentioned in free text (longest phrase wins at the same position)."""
    if not text:
        return None
    tokens = tokenise(text)
    best: tuple[int, int, str] | None = None  # (position, -length, colour)
    for phrase in _BY_LENGTH:
        phrase_tokens = phrase.split()
        positions = find_phrase(tokens, phrase_tokens)
        if positions:
            key = (positions[0], -len(phrase_tokens), _SYNONYMS[phrase])
            if best is None or key < best:
                best = key
    return best[2] if best else None


def colour_phrases() -> set[str]:
    return set(_SYNONYMS) | set(_FIELD_ONLY)
