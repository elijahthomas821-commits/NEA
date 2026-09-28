"""Condition normalisation: marketplace labels and free-text wording → :class:`Condition`.

Phrases are matched on whole tokens, longest first, so "new without tags" never matches
"new with tags" and "very good" wins over "good". Ambiguous single words ("good", "fair") are
only trusted in structured fields and your own notes, not in a seller's title or description
("good quality cotton" is not a condition grade).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.analysis.normalisation.text import find_phrase, normalise_text, tokenise
from app.core.enums import Condition

ConditionSource = Literal["field", "notes", "title", "description"]

# (phrase, condition, safe_in_free_text)
_PHRASES: list[tuple[str, Condition, bool]] = [
    ("new with tags", Condition.NEW_WITH_TAGS, True),
    ("new with tag", Condition.NEW_WITH_TAGS, True),
    ("brand new with tags", Condition.NEW_WITH_TAGS, True),
    ("bnwt", Condition.NEW_WITH_TAGS, True),
    ("nwt", Condition.NEW_WITH_TAGS, True),
    ("tags attached", Condition.NEW_WITH_TAGS, True),
    ("tags still attached", Condition.NEW_WITH_TAGS, True),
    ("still has tags", Condition.NEW_WITH_TAGS, True),
    ("new without tags", Condition.NEW_WITHOUT_TAGS, True),
    ("new without tag", Condition.NEW_WITHOUT_TAGS, True),
    ("bnwot", Condition.NEW_WITHOUT_TAGS, True),
    ("nwot", Condition.NEW_WITHOUT_TAGS, True),
    ("never worn", Condition.NEW_WITHOUT_TAGS, True),
    ("unworn", Condition.NEW_WITHOUT_TAGS, True),
    ("very good", Condition.VERY_GOOD, True),
    ("vgc", Condition.VERY_GOOD, True),
    ("excellent condition", Condition.VERY_GOOD, True),
    ("excellent", Condition.VERY_GOOD, False),
    ("mint condition", Condition.VERY_GOOD, True),
    ("like new", Condition.VERY_GOOD, True),
    ("worn once", Condition.VERY_GOOD, True),
    ("worn twice", Condition.VERY_GOOD, True),
    ("great condition", Condition.VERY_GOOD, True),
    ("immaculate", Condition.VERY_GOOD, True),
    ("good condition", Condition.GOOD, True),
    ("good cond", Condition.GOOD, True),
    ("gc", Condition.GOOD, False),
    ("good", Condition.GOOD, False),
    ("used", Condition.GOOD, False),
    ("satisfactory", Condition.SATISFACTORY, True),
    ("fair condition", Condition.SATISFACTORY, True),
    ("fair", Condition.SATISFACTORY, False),
    ("well worn", Condition.SATISFACTORY, True),
    ("heavily worn", Condition.SATISFACTORY, True),
    ("signs of wear", Condition.SATISFACTORY, True),
    ("some wear", Condition.SATISFACTORY, True),
]
_PHRASES_BY_LENGTH = sorted(_PHRASES, key=lambda p: -len(p[0].split()))

_DAMAGE_TERMS = [
    "hole",
    "holes",
    "stain",
    "stains",
    "stained",
    "rip",
    "ripped",
    "tear",
    "torn",
    "damaged",
    "damage",
    "bobbling",
    "pilling",
    "missing button",
    "broken zip",
    "zip broken",
    "needs repair",
    "for repair",
    "faulty",
    "discoloured",
    "discolored",
    "bleach mark",
]
_NEGATORS = {"no", "not", "without", "zero", "free", "never"}


class ConditionMatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    condition: Condition
    source: ConditionSource
    matched: str


def match_condition(text: str | None, source: ConditionSource) -> ConditionMatch | None:
    """Best condition phrase in ``text``. Structured sources accept ambiguous words too."""
    if not text:
        return None
    tokens = tokenise(text)
    structured = source in ("field", "notes")
    best: tuple[int, int, str, Condition] | None = None  # (-length, position, phrase, cond)
    for phrase, condition, text_ok in _PHRASES_BY_LENGTH:
        if not (text_ok or structured):
            continue
        phrase_tokens = phrase.split()
        positions = find_phrase(tokens, phrase_tokens)
        if not positions:
            continue
        # Negated wording ("no signs of wear") does not describe the condition.
        start = positions[0]
        if start > 0 and tokens[start - 1] in _NEGATORS:
            continue
        key = (-len(phrase_tokens), start, phrase, condition)
        if best is None or key[:2] < best[:2]:
            best = key
    if best is None:
        return None
    return ConditionMatch(condition=best[3], source=source, matched=best[2])


# Condition labels used by marketplaces' structured condition selectors, in the languages of
# the sites you might buy from (English, French, German, Italian, Spanish, Dutch).
_MARKETPLACE_LABELS: dict[Condition, list[str]] = {
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
}  # fmt: skip
_LABEL_LOOKUP: dict[str, Condition] = {
    normalise_text(label): condition
    for condition, labels in _MARKETPLACE_LABELS.items()
    for label in labels
}


def match_condition_label(label: str | None) -> Condition | None:
    """Exact condition labels from a structured field ("Very good", "very_good", "Sehr gut")."""
    if not label:
        return None
    norm = normalise_text(label.replace("_", " "))
    return _LABEL_LOOKUP.get(norm)


def find_damage_terms(text: str | None) -> list[str]:
    """Damage wording ("small hole", "stain on cuff"), ignoring negations ("no stains")."""
    if not text:
        return []
    tokens = tokenise(text)
    found: list[str] = []
    for term in _DAMAGE_TERMS:
        term_tokens = term.split()
        for start in find_phrase(tokens, term_tokens):
            window = tokens[max(0, start - 3) : start]
            if any(tok in _NEGATORS for tok in window):
                continue
            if term not in found:
                found.append(term)
            break
    return found
