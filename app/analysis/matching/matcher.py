"""Canonical product matching.

Candidates are the products of the identified brand (and category, when known). Each is scored
by its best alias: an exact model code is strongest, then a whole-phrase alias match (longer
aliases are more specific, so they score higher), then a fuzzy match for misspellings. The best
candidate wins only if it clears ``min_score`` *and* beats the runner-up by ``min_margin``;
otherwise the listing falls back to the brand × category "any model" product. Nothing here
invents a product.

Confidence:

* specific product: brand confidence × alias strength (the product implies the category;
  × ``inferred_category_factor`` when the category had to be inferred from the product);
* "any model" fallback: brand confidence × category confidence. Its lower precision is
  accounted for later, because it can only be priced from broader comparable-sales levels.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.identification.types import IdentificationResult
from app.analysis.normalisation.text import best_fuzzy_match, find_phrase, tokenise
from app.config.schemas import MatchingRules
from app.core.enums import ProductLevel

MatchMethod = Literal["model_code", "alias", "fuzzy", "generic", "none"]


class ProductAliasEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str  # normalised
    weight: Decimal = Decimal(1)


class ProductEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    brand_id: int
    category_id: int
    level: ProductLevel
    name: str
    model_code: str | None = None
    aliases: list[ProductAliasEntry] = Field(default_factory=list)


class MatchCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    product_id: int
    name: str
    score: Decimal
    via: str


class MatchResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    product_id: int | None = None
    product_level: ProductLevel | None = None
    category_id: int | None = None
    confidence: Decimal = Decimal(0)
    method: MatchMethod = "none"
    candidates: list[MatchCandidate] = Field(default_factory=list)
    ambiguous: bool = False
    note: str | None = None


def _alias_score(
    alias: ProductAliasEntry, tokens: list[str], fuzzy_tokens: list[str], fuzzy_min: float
) -> tuple[Decimal, str]:
    """Exact phrases are matched on the full text; fuzzy matching only on the leftover words
    (brand, category, size and colour words removed) to avoid near-misses on common words."""
    alias_tokens = alias.text.split()
    if not alias_tokens:
        return Decimal(0), ""
    if find_phrase(tokens, alias_tokens):
        specificity = Decimal("0.75") + Decimal("0.05") * min(len(alias_tokens), 4)
        return alias.weight * specificity, f"alias '{alias.text}'"
    if len(alias.text.replace(" ", "")) >= 6:
        similarity, gram = best_fuzzy_match(fuzzy_tokens, alias.text)
        if gram is not None and similarity >= fuzzy_min:
            score = alias.weight * Decimal(str(round(similarity, 3))) * Decimal("0.8")
            return score, f"fuzzy '{gram}' ~ '{alias.text}'"
    return Decimal(0), ""


def _score_product(
    product: ProductEntry, tokens: list[str], fuzzy_tokens: list[str], fuzzy_min: float
) -> tuple[Decimal, str, MatchMethod]:
    if product.model_code:
        code_tokens = tokenise(product.model_code)
        if code_tokens and find_phrase(tokens, code_tokens):
            return Decimal("0.95"), f"model code {product.model_code}", "model_code"
    best: tuple[Decimal, str, MatchMethod] = (Decimal(0), "", "none")
    for alias in product.aliases:
        score, via = _alias_score(alias, tokens, fuzzy_tokens, fuzzy_min)
        if score > best[0]:
            best = (score, via, "fuzzy" if via.startswith("fuzzy") else "alias")
    return best


def match_product(
    ident: IdentificationResult,
    products: list[ProductEntry],
    rules: MatchingRules,
    *,
    hint_text: str | None = None,
) -> MatchResult:
    """Match ``ident`` to one of ``products`` (all products of the identified brand)."""
    if ident.brand_id is None:
        return MatchResult(note="brand unknown")

    tokens = list(ident.tokens)
    fuzzy_tokens = list(ident.model_tokens)
    if hint_text:
        hint = tokenise(hint_text)
        tokens = [*tokens, *hint]
        fuzzy_tokens = [*fuzzy_tokens, *hint]
    fuzzy_min = float(rules.fuzzy_min_similarity)
    brand_products = [p for p in products if p.brand_id == ident.brand_id]
    specific = [
        p
        for p in brand_products
        if p.level != ProductLevel.BRAND_CATEGORY_GENERIC
        and (ident.category_id is None or p.category_id == ident.category_id)
    ]

    scored: list[tuple[Decimal, ProductEntry, str, MatchMethod]] = []
    for product in specific:
        score, via, method = _score_product(product, tokens, fuzzy_tokens, fuzzy_min)
        if score > 0:
            scored.append((score, product, via, method))
    scored.sort(key=lambda item: (-item[0], item[1].id))
    candidates = [
        MatchCandidate(product_id=p.id, name=p.name, score=s.quantize(Decimal("0.001")), via=via)
        for s, p, via, _ in scored[:5]
    ]

    ambiguous = False
    if scored and scored[0][0] >= rules.min_score:
        top_score, top, _, method = scored[0]
        runner_up = scored[1][0] if len(scored) > 1 else Decimal(0)
        if top_score - runner_up >= rules.min_margin:
            confidence = top_score * ident.brand_confidence
            if ident.category_id is None:
                confidence *= rules.inferred_category_factor
            confidence = confidence.quantize(Decimal("0.001"))
            return MatchResult(
                product_id=top.id,
                product_level=top.level,
                category_id=top.category_id,
                confidence=confidence,
                method=method,
                candidates=candidates,
            )
        ambiguous = True

    category_id = ident.category_id
    generic = next(
        (
            p
            for p in brand_products
            if p.level == ProductLevel.BRAND_CATEGORY_GENERIC and p.category_id == category_id
        ),
        None,
    )
    if generic is None or category_id is None:
        return MatchResult(
            candidates=candidates,
            ambiguous=ambiguous,
            note="no specific product and no brand x category fallback",
        )
    confidence = (ident.brand_confidence * ident.category_confidence).quantize(Decimal("0.001"))
    return MatchResult(
        product_id=generic.id,
        product_level=generic.level,
        category_id=generic.category_id,
        confidence=confidence,
        method="generic",
        candidates=candidates,
        ambiguous=ambiguous,
        note="several products matched equally well" if ambiguous else None,
    )
