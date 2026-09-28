"""Rules-based identification.

Sources, most to least trusted: your own notes, the marketplace's structured fields, the title,
the description. Disagreements between sources are recorded as contradictions (they lower
confidence and can route a listing to REVIEW) rather than silently resolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from app.analysis.identification.types import (
    BrandEntry,
    BrandSource,
    Catalogue,
    CategoryEntry,
    CategorySource,
    Contradiction,
    IdentificationResult,
    ListingText,
)
from app.analysis.normalisation.colour import colour_phrases, find_colour, normalise_colour_field
from app.analysis.normalisation.condition import (
    ConditionSource,
    find_damage_terms,
    match_condition,
    match_condition_label,
)
from app.analysis.normalisation.size import (
    UNKNOWN,
    SizeResult,
    find_size_in_text,
    is_kids_text,
    parse_size_value,
    size_tokens,
)
from app.analysis.normalisation.text import (
    best_fuzzy_match,
    find_phrase,
    normalise_text,
    tokenise,
    trigram_similarity,
)
from app.config.schemas import IdentificationConfig, SizesConfig
from app.core.enums import Condition

ONE = Decimal(1)
MAX_CONFIDENCE = Decimal("0.99")
_STYLE_WORDS = {"style", "inspired", "type", "look", "esque", "alike", "lookalike"}
_NEGATORS = {"not", "no", "never", "isnt", "non", "zero", "nothing", "without"}
_STOPWORDS = {
    "the", "a", "an", "and", "with", "in", "for", "of", "on", "to", "mens", "men", "man",
    "womens", "women", "unisex", "size", "sz", "genuine", "authentic", "original", "real",
    "vintage", "rare", "bnwt", "nwt", "condition", "worn", "great", "very", "good", "new",
    "tags", "tag", "only", "item", "top", "quality", "price", "ono", "offers", "free", "postage",
}  # fmt: skip


def _combine(a: Decimal, b: Decimal) -> Decimal:
    """Two independent sources agreeing: 1 - (1-a)(1-b), capped."""
    return min(MAX_CONFIDENCE, ONE - (ONE - a) * (ONE - b))


def _q(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.001"))


@dataclass(frozen=True)
class _BrandHit:
    brand: BrandEntry
    source: BrandSource
    position: int
    matched: str
    negated: bool = False
    fuzzy: bool = False


def _hits_in(tokens: list[str], catalogue: Catalogue, source: BrandSource) -> list[_BrandHit]:
    hits: list[_BrandHit] = []
    for brand in catalogue.brands:
        negated_by_alias = next(
            (neg for neg in brand.negative_aliases if find_phrase(tokens, neg.split())), None
        )
        best: _BrandHit | None = None
        for alias in sorted(brand.aliases, key=lambda a: -len(a.split())):
            alias_tokens = alias.split()
            for pos in find_phrase(tokens, alias_tokens):
                after = (
                    tokens[pos + len(alias_tokens)] if pos + len(alias_tokens) < len(tokens) else ""
                )
                before = tokens[pos - 1] if pos > 0 else ""
                negated = (
                    negated_by_alias is not None or after in _STYLE_WORDS or before in _NEGATORS
                )
                hit = _BrandHit(brand, source, pos, alias, negated=negated)
                if best is None or pos < best.position:
                    best = hit
        if best is not None:
            hits.append(best)
    return hits


def _fuzzy_hits(
    tokens: list[str], catalogue: Catalogue, config: IdentificationConfig
) -> list[_BrandHit]:
    threshold = float(config.brand_fuzzy_min_similarity)
    hits: list[_BrandHit] = []
    for brand in catalogue.brands:
        best: tuple[float, str] | None = None
        for alias in brand.aliases:
            if len(alias.replace(" ", "")) < 6:
                continue  # short aliases produce too many false fuzzy matches
            similarity, gram = best_fuzzy_match(tokens, alias)
            if (
                gram is not None
                and similarity >= threshold
                and (best is None or similarity > best[0])
            ):
                best = (similarity, gram)
        if best is not None:
            position = next((i for i, t in enumerate(tokens) if t == best[1].split()[0]), 0)
            hits.append(_BrandHit(brand, "fuzzy", position, best[1], fuzzy=True))
    return hits


def _field_brand(
    raw_brand: str | None, catalogue: Catalogue, config: IdentificationConfig
) -> tuple[_BrandHit | None, bool, str | None]:
    """Returns (hit, field_is_generic, unknown_brand_text)."""
    if not raw_brand:
        return None, False, None
    norm = normalise_text(raw_brand)
    generic = {normalise_text(v) for v in config.generic_brand_values}
    if norm in generic:
        return None, True, None
    tokens = norm.split()
    hits = [h for h in _hits_in(tokens, catalogue, "field") if not h.negated]
    if hits:
        return min(hits, key=lambda h: h.position), False, None
    threshold = float(config.brand_fuzzy_min_similarity)
    best: tuple[float, BrandEntry, str] | None = None
    for brand in catalogue.brands:
        for alias in brand.aliases:
            similarity = trigram_similarity(norm, alias)
            if similarity >= threshold and (best is None or similarity > best[0]):
                best = (similarity, brand, alias)
    if best is not None:
        return _BrandHit(best[1], "field", 0, best[2], fuzzy=True), False, None
    return None, False, raw_brand.strip()


def _replica_terms(tokens: list[str], config: IdentificationConfig) -> list[str]:
    found: list[str] = []
    for phrase in config.replica_phrases:
        phrase_tokens = normalise_text(phrase).split()
        if not phrase_tokens:
            continue
        for pos in find_phrase(tokens, phrase_tokens):
            window = tokens[max(0, pos - 2) : pos]
            if any(t in _NEGATORS for t in window):
                continue
            if phrase not in found:
                found.append(phrase)
            break
    return found


def _best_category(tokens: list[str], catalogue: Catalogue) -> tuple[CategoryEntry, str] | None:
    best: tuple[int, int, int, CategoryEntry, str] | None = None
    for category in catalogue.categories:
        for keyword in category.keywords:
            keyword_tokens = keyword.split()
            positions = find_phrase(tokens, keyword_tokens)
            if positions:
                # Longest phrase, then priority, then earliest position.
                key = (len(keyword_tokens), category.priority, -positions[0])
                if best is None or key > best[:3]:
                    best = (*key, category, keyword)
    return (best[3], best[4]) if best else None


def identify(
    listing: ListingText,
    catalogue: Catalogue,
    config: IdentificationConfig,
    sizes: SizesConfig,
) -> IdentificationResult:
    title_tokens = tokenise(listing.title)
    notes_tokens = tokenise(listing.operator_notes)
    desc_tokens = tokenise(listing.description)
    all_tokens = [*title_tokens, *notes_tokens, *desc_tokens]
    evidence: list[str] = []
    contradictions: list[Contradiction] = []

    # ------------------------------------------------------------------ brand
    field_hit, field_generic, unknown_brand = _field_brand(listing.raw_brand, catalogue, config)
    notes_hits = [h for h in _hits_in(notes_tokens, catalogue, "notes") if not h.negated]
    title_all = _hits_in(title_tokens, catalogue, "title")
    title_hits = [h for h in title_all if not h.negated]
    if not title_all:
        title_hits = _fuzzy_hits(title_tokens, catalogue, config)
    desc_hits = [h for h in _hits_in(desc_tokens, catalogue, "description") if not h.negated]
    negated_hits = [h for h in title_all if h.negated] + [
        h for h in _hits_in(desc_tokens, catalogue, "description") if h.negated
    ]
    replica_terms = _replica_terms(all_tokens, config)
    for hit in negated_hits:
        term = f"{hit.matched} (look-alike wording)"
        if term not in replica_terms:
            replica_terms.append(term)

    chosen: _BrandHit | None = None
    confidence = Decimal(0)
    title_brand_ids = {h.brand.id for h in title_hits}

    if notes_hits:
        chosen = min(notes_hits, key=lambda h: h.position)
        confidence = config.brand_field_confidence
        evidence.append(f"brand '{chosen.brand.name}' from your notes")
        if field_hit is not None and field_hit.brand.id != chosen.brand.id:
            contradictions.append(
                Contradiction(
                    code="BRAND_NOTES_FIELD_MISMATCH",
                    detail=f"you said {chosen.brand.name}; brand field says {field_hit.brand.name}",
                )
            )
    elif field_hit is not None:
        chosen = field_hit
        confidence = config.brand_field_confidence
        if field_hit.fuzzy:
            confidence *= config.brand_fuzzy_factor
        evidence.append(f"brand '{field_hit.brand.name}' from the brand field")
        if field_hit.brand.id in title_brand_ids:
            confidence = _combine(confidence, config.brand_title_confidence)
            evidence.append("title agrees with the brand field")
        elif title_brand_ids:
            other = next(h for h in title_hits if h.brand.id != field_hit.brand.id)
            contradictions.append(
                Contradiction(
                    code="BRAND_FIELD_TITLE_MISMATCH",
                    detail=(
                        f"brand field says {field_hit.brand.name}; title says {other.brand.name}"
                    ),
                )
            )
            confidence *= config.contradiction_factor
    elif title_hits:
        chosen = min(title_hits, key=lambda h: h.position)
        confidence = config.brand_title_confidence
        if chosen.fuzzy:
            confidence *= config.brand_fuzzy_factor
            evidence.append(f"title looks like '{chosen.brand.name}' (spelled '{chosen.matched}')")
        else:
            evidence.append(f"title mentions '{chosen.matched}'")
        if len(title_brand_ids) > 1:
            names = sorted({h.brand.name for h in title_hits})
            contradictions.append(
                Contradiction(code="MULTIPLE_BRANDS", detail="title names " + ", ".join(names))
            )
            confidence *= config.contradiction_factor
        if unknown_brand:
            contradictions.append(
                Contradiction(
                    code="BRAND_FIELD_TITLE_MISMATCH",
                    detail=f"brand field says {unknown_brand}; title says {chosen.brand.name}",
                )
            )
            confidence *= config.contradiction_factor
        elif field_generic:
            evidence.append(
                f"brand field says '{listing.raw_brand}' although the title names a brand"
            )
            confidence *= Decimal("0.9")
    elif desc_hits:
        chosen = min(desc_hits, key=lambda h: h.position)
        confidence = config.brand_description_confidence
        evidence.append(f"brand '{chosen.brand.name}' only mentioned in the description")
        if len({h.brand.id for h in desc_hits}) > 1:
            contradictions.append(
                Contradiction(code="MULTIPLE_BRANDS", detail="description names several brands")
            )
            confidence *= config.contradiction_factor
    elif unknown_brand:
        evidence.append(f"brand '{unknown_brand}' is not in the catalogue")
    elif field_generic:
        evidence.append(f"brand field says '{listing.raw_brand}'")

    if chosen is not None and replica_terms:
        confidence *= config.replica_factor
        evidence.append("replica/look-alike wording: " + ", ".join(replica_terms))

    # ------------------------------------------------------------------ category
    category: CategoryEntry | None = None
    category_source: CategorySource | None = None
    category_confidence = Decimal(0)
    notes_cat = _best_category(notes_tokens, catalogue)
    field_cat = _best_category(tokenise(listing.raw_category), catalogue)
    title_cat = _best_category(title_tokens, catalogue)
    desc_cat = _best_category(desc_tokens, catalogue)
    if notes_cat:
        category, category_source = notes_cat[0], "notes"
        category_confidence = config.category_field_confidence
    elif field_cat and title_cat:
        if field_cat[0].id == title_cat[0].id:
            category, category_source = field_cat[0], "field"
            category_confidence = _combine(
                config.category_field_confidence, config.category_title_confidence
            )
        elif (
            field_cat[0].parent_id is not None and field_cat[0].parent_id == title_cat[0].parent_id
        ):
            # e.g. field "Hoodies & sweatshirts" (→ sweatshirts), title "hoodie": the title is
            # more specific within the same family.
            category, category_source = title_cat[0], "title"
            category_confidence = config.category_title_confidence
        else:
            category, category_source = field_cat[0], "field"
            category_confidence = config.category_field_confidence * config.contradiction_factor
            contradictions.append(
                Contradiction(
                    code="CATEGORY_MISMATCH",
                    detail=(
                        f"category field says {field_cat[0].name}; title says {title_cat[0].name}"
                    ),
                )
            )
    elif field_cat:
        category, category_source = field_cat[0], "field"
        category_confidence = config.category_field_confidence
    elif title_cat:
        category, category_source = title_cat[0], "title"
        category_confidence = config.category_title_confidence
    elif desc_cat:
        category, category_source = desc_cat[0], "description"
        category_confidence = config.brand_description_confidence
    if category is not None:
        evidence.append(f"category '{category.name}' from the {category_source}")

    # ------------------------------------------------------------------ size
    brand_slug = chosen.brand.slug if chosen else None
    size = _identify_size(listing, brand_slug, sizes, contradictions)

    # ------------------------------------------------------------------ colour
    colour = (
        normalise_colour_field(listing.raw_colour)
        or find_colour(listing.operator_notes)
        or find_colour(listing.title)
        or find_colour(listing.description)
    )

    # ------------------------------------------------------------------ condition
    condition, condition_source = _identify_condition(listing)
    damage_terms = find_damage_terms(
        " ".join(filter(None, [listing.title, listing.description, listing.operator_notes]))
    )

    # ------------------------------------------------------------------ leftover tokens
    removable: set[str] = set(_STOPWORDS) | size_tokens(size)
    if chosen is not None:
        for alias in chosen.brand.aliases:
            removable.update(alias.split())
    if category is not None:
        for keyword in category.keywords:
            removable.update(keyword.split())
    for phrase in colour_phrases():
        removable.update(phrase.split())
    model_tokens = [t for t in [*title_tokens, *notes_tokens] if t not in removable]

    return IdentificationResult(
        brand_id=chosen.brand.id if chosen else None,
        brand_slug=chosen.brand.slug if chosen else None,
        brand_confidence=_q(confidence),
        brand_source=chosen.source if chosen else None,
        brand_field_generic=field_generic,
        unknown_brand=unknown_brand,
        category_id=category.id if category else None,
        category_slug=category.slug if category else None,
        category_in_scope=category.in_scope if category else None,
        category_confidence=_q(category_confidence),
        category_source=category_source,
        size=size,
        colour=colour,
        condition=condition,
        condition_source=condition_source,
        damage_terms=damage_terms,
        replica_terms=replica_terms,
        contradictions=contradictions,
        evidence=evidence,
        tokens=[*title_tokens, *notes_tokens],
        model_tokens=model_tokens,
    )


def _identify_size(
    listing: ListingText,
    brand_slug: str | None,
    sizes: SizesConfig,
    contradictions: list[Contradiction],
) -> SizeResult:
    field = parse_size_value(listing.raw_size, brand_slug=brand_slug, config=sizes, source="field")
    notes = find_size_in_text(
        listing.operator_notes,
        brand_slug=brand_slug,
        config=sizes,
        source="notes",
        case_insensitive_letters=True,
    )
    title = find_size_in_text(listing.title, brand_slug=brand_slug, config=sizes, source="title")
    kids = is_kids_text(listing.title) or is_kids_text(listing.description)

    chosen: SizeResult = UNKNOWN
    for candidate in (notes, field, title):
        if candidate.known or candidate.is_kids:
            chosen = candidate
            break
    if not chosen.known and not chosen.is_kids:
        chosen = find_size_in_text(
            listing.description, brand_slug=brand_slug, config=sizes, source="description"
        )
    if field.known and title.known and field.normalised != title.normalised:
        contradictions.append(
            Contradiction(
                code="SIZE_MISMATCH",
                detail=f"size field says {field.normalised}; title says {title.normalised}",
            )
        )
    if kids and not chosen.is_kids:
        chosen = chosen.model_copy(update={"is_kids": True})
    return chosen


def _identify_condition(listing: ListingText) -> tuple[Condition | None, str | None]:
    if listing.raw_condition:
        label = match_condition_label(listing.raw_condition)
        if label is not None:
            return label, "field"
        match = match_condition(listing.raw_condition, "field")
        if match is not None:
            return match.condition, "field"
    sources: list[tuple[str | None, ConditionSource]] = [
        (listing.operator_notes, "notes"),
        (listing.title, "title"),
        (listing.description, "description"),
    ]
    for text, source in sources:
        match = match_condition(text, source)
        if match is not None:
            return match.condition, source
    return None, None
