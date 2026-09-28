import pytest

from app.analysis.normalisation.text import (
    best_fuzzy_match,
    contains_phrase,
    find_phrase,
    ngrams,
    normalise_text,
    slugify,
    tokenise,
    trigram_similarity,
    unique_normalised,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("C.P. Company Goggle Hoodie – Navy!", "cp company goggle hoodie navy"),
        ("STONE ISLAND", "stone island"),
        ("Moncler Grenoble — Café", "moncler grenoble cafe"),
        ("men's hoodie", "mens hoodie"),
        ("Hoodies & Sweatshirts", "hoodies and sweatshirts"),
        ("1:1 quality", "1 1 quality"),
        ("t-shirt", "t shirt"),
        ("Soft Shell-R e.dye", "soft shell r e dye"),
        ("   ", ""),
        (None, ""),
        ("🔥 Stone Island 🔥", "stone island"),
    ],
)
def test_normalise_text(raw, expected):
    assert normalise_text(raw) == expected


def test_tokenise():
    assert tokenise("Stone Island, Crinkle-Reps!") == ["stone", "island", "crinkle", "reps"]


def test_find_phrase_is_token_based():
    tokens = tokenise("new without tags")
    assert find_phrase(tokens, ["new", "with", "tags"]) == []
    assert contains_phrase(tokens, ["without", "tags"])
    assert find_phrase(tokenise("a b a b"), ["a", "b"]) == [0, 2]


def test_ngrams():
    assert ngrams(["a", "b", "c"], 2) == ["a b", "b c"]
    assert ngrams(["a"], 2) == []


def test_trigram_similarity():
    assert trigram_similarity("stone island", "stone island") == 1.0
    assert trigram_similarity("stone island", "stone iland") > 0.6
    assert trigram_similarity("stone island", "moncler") < 0.2
    assert trigram_similarity("", "x") == 0.0


def test_best_fuzzy_match_finds_misspelling():
    sim, gram = best_fuzzy_match(tokenise("vintage stone islnad crewneck"), "stone island")
    assert gram == "stone islnad"
    assert sim > 0.5


def test_unique_normalised_dedupes():
    assert unique_normalised(["Hoodie", "hoodie", "", "HOODIE!"]) == ["hoodie"]


def test_slugify():
    assert slugify("C.P. Company Lens Hoodie") == "cp-company-lens-hoodie"
