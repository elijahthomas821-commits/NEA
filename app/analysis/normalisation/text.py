"""Text normalisation and phrase matching.

The same :func:`normalise_text` is used for catalogue aliases and for listing text, so an alias
matches whenever the listing contains the same words, whatever the punctuation, accents or
case ("C.P. Company", "c.p company" and "CP COMPANY" all become ``"cp company"``).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence

_INITIALISM = re.compile(r"\b(?:[a-z]\.){2,}")
_APOSTROPHES = re.compile(r"['‘’`´]")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalise_text(value: str | None) -> str:
    """Lower-case, strip accents, drop punctuation, collapse whitespace.

    ``"C.P. Company Goggle Hoodie – Navy!"`` → ``"cp company goggle hoodie navy"``
    """
    if not value:
        return ""
    text = unicodedata.normalize("NFKD", value)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.casefold()
    text = _APOSTROPHES.sub("", text)
    text = text.replace("&", " and ")
    # "c.p." → "cp", "s.i." → "si" (initialisms), before dots become spaces.
    text = _INITIALISM.sub(lambda m: m.group(0).replace(".", ""), text)
    text = _NON_ALNUM.sub(" ", text)
    return " ".join(text.split())


def tokenise(value: str | None) -> list[str]:
    return normalise_text(value).split()


def find_phrase(tokens: Sequence[str], phrase: Sequence[str]) -> list[int]:
    """Start indices where ``phrase`` occurs as a contiguous token run in ``tokens``."""
    n, m = len(tokens), len(phrase)
    if m == 0 or m > n:
        return []
    first = phrase[0]
    return [
        i
        for i in range(n - m + 1)
        if tokens[i] == first and list(tokens[i : i + m]) == list(phrase)
    ]


def contains_phrase(tokens: Sequence[str], phrase: Sequence[str]) -> bool:
    return bool(find_phrase(tokens, phrase))


def ngrams(tokens: Sequence[str], n: int) -> list[str]:
    if n <= 0 or n > len(tokens):
        return []
    return [" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


def trigrams(value: str) -> set[str]:
    """Character trigrams in the style of PostgreSQL ``pg_trgm`` (words padded with spaces)."""
    grams: set[str] = set()
    for word in normalise_text(value).split():
        padded = f"  {word} "
        grams.update(padded[i : i + 3] for i in range(len(padded) - 2))
    return grams


def trigram_similarity(a: str, b: str) -> float:
    """Jaccard similarity of trigram sets, 0-1 (1 = identical after normalisation)."""
    ta, tb = trigrams(a), trigrams(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def best_fuzzy_match(tokens: Sequence[str], phrase: str) -> tuple[float, str | None]:
    """Best trigram similarity between ``phrase`` and any n-gram of ``tokens`` of similar length.

    Used to catch misspellings ("stone iland"). Returns ``(similarity, matched_ngram)``.
    """
    phrase_len = len(phrase.split())
    best: tuple[float, str | None] = (0.0, None)
    for n in {max(1, phrase_len - 1), phrase_len, phrase_len + 1}:
        for gram in ngrams(tokens, n):
            sim = trigram_similarity(gram, phrase)
            if sim > best[0]:
                best = (sim, gram)
    return best


def unique_normalised(values: Iterable[str]) -> list[str]:
    """Normalise and de-duplicate, preserving order and dropping empties."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        norm = normalise_text(value)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def slugify(value: str) -> str:
    return normalise_text(value).replace(" ", "-")
