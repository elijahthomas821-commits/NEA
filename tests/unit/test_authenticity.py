import re
from datetime import date
from decimal import Decimal

import pytest

from app.analysis.authenticity.risk import (
    AuthenticityInputs,
    ChecklistObservation,
    SellerSignals,
    assess_authenticity,
)
from app.config.loader import load_default_config
from app.core.enums import CheckResult, ConfigKind, RiskLevel

D = Decimal
CFG = load_default_config(ConfigKind.AUTHENTICITY)
TODAY = date(2026, 9, 1)


def assess(**overrides):
    data = {
        "brand_slug": "stone-island",
        "brand_base_risk": D("0.35"),
        "price": D("60"),
        "comps_median": D("110"),
        "text": "Stone Island crewneck",
        "photo_count": 4,
        "as_of": TODAY,
    }
    data.update(overrides)
    return assess_authenticity(AuthenticityInputs(**data), CFG)


def test_prior_only():
    result = assess(price=None, comps_median=None)
    assert result.risk_score == D("0.350")
    assert result.signals == []
    assert not result.has_warning_signs


def test_evidence_lowers_risk_below_the_prior():
    result = assess(
        price=D("90"),
        seller=SellerSignals(rating=D("4.9"), review_count=240),
        checklist=[
            ChecklistObservation(code="compass_badge", result=CheckResult.OBSERVED),
            ChecklistObservation(code="authenticity_label", result=CheckResult.OBSERVED),
            ChecklistObservation(code="care_labels", result=CheckResult.OBSERVED),
        ],
    )
    assert result.risk_score < D("0.10")
    assert result.risk_level is RiskLevel.LOW
    assert not result.has_warning_signs
    assert any("compass badge" in e.lower() for e in result.evidence)


def test_severe_price_anomaly():
    result = assess(price=D("30"))  # < 110 × 0.35 = 38.50
    assert result.price_anomaly
    assert result.has_warning_signs
    assert result.risk_level is RiskLevel.HIGH
    assert "Ask why the price is so low and for proof of purchase" in result.recommended_checks


def test_moderate_price_anomaly():
    result = assess(price=D("45"))  # < 110 × 0.50 = 55
    assert {s.code for s in result.signals} == {"PRICE_ANOMALY_MODERATE"}
    assert not result.price_anomaly  # moderate adds risk but is not "too good to be true"


def test_typical_flip_price_is_not_suspicious():
    result = assess(price=D("70"))  # 64% of the median
    assert {s.code for s in result.signals} == {"PRICE_NORMAL"}


def test_replica_language_dominates():
    result = assess(price=D("90"), replica_terms=["1 1", "replica"])
    assert result.risk_score > D("0.95")


def test_signals_combine():
    one = assess(price=D("90"), seller=SellerSignals(review_count=1))
    two = assess(price=D("90"), seller=SellerSignals(review_count=1, rating=D("3.9")))
    assert two.risk_score > one.risk_score


def test_new_account_and_trusted_seller():
    new = assess(price=D("90"), seller=SellerSignals(member_since=date(2026, 8, 25)))
    trusted = assess(price=D("90"), seller=SellerSignals(operator_flag="trusted"))
    base = assess(price=D("90"))
    assert new.risk_score > base.risk_score > trusted.risk_score


def test_blocked_seller_is_maximal():
    result = assess(price=D("90"), seller=SellerSignals(operator_flag="blocked"))
    assert result.risk_score > D("0.99")


def test_reused_photos_and_mislabel_and_contradictions():
    base = assess(price=D("90")).risk_score
    for kwargs in ({"reused_photo_matches": 1}, {"mislabel": True}, {"contradiction_count": 2}):
        assert assess(price=D("90"), **kwargs).risk_score > base


def test_missing_tags_language():
    result = assess(price=D("90"), text="Stone Island crewneck, tags removed")
    assert any(s.code == "MISSING_TAGS" for s in result.signals)


def test_checklist_concern_raises_risk_and_suggests_check():
    result = assess(
        price=D("90"),
        checklist=[
            ChecklistObservation(
                code="compass_badge", result=CheckResult.CONCERN, note="blurry font"
            )
        ],
    )
    assert result.has_warning_signs
    assert (
        "Ask for a close, straight-on photo of the compass badge (front)"
        in result.recommended_checks
    )


def test_unknown_checklist_codes_ignored():
    result = assess(
        price=D("90"), checklist=[ChecklistObservation(code="made_up", result=CheckResult.CONCERN)]
    )
    assert not result.has_warning_signs


def test_confidence():
    none = assess(photo_count=0)
    some = assess(photo_count=2)
    lots = assess(
        photo_count=6,
        seller=SellerSignals(review_count=10, rating=D("4.9")),
        checklist=[ChecklistObservation(code="compass_badge", result=CheckResult.OBSERVED)],
    )
    assert none.confidence <= CFG.confidence.no_photos_cap
    assert none.recommended_checks[0].startswith("Ask the seller for more photos")
    assert none.confidence < some.confidence < lots.confidence
    assert lots.confidence <= CFG.confidence.maximum


@pytest.mark.parametrize("price", [D("20"), D("45"), D("90"), None])
def test_output_never_claims_authenticity(price):
    result = assess(price=price, replica_terms=["replica"] if price == D("20") else [])
    texts = [*result.evidence, *result.concerns, *result.recommended_checks]
    assert not [t for t in texts if re.search(r"\b(authentic|genuine|legit|real)\b", t, re.I)]


def test_documented_example():
    """docs/financial-calculations.md section 8."""
    result = assess(
        price=D("45"),
        comps_median=D("110"),
        seller=SellerSignals(rating=D("4.9"), review_count=120),
        checklist=[
            ChecklistObservation(code=code, result=CheckResult.OBSERVED)
            for code in ("compass_badge", "badge_back", "authenticity_label", "care_labels")
        ],
    )
    assert result.risk_score == D("0.083")
    assert result.risk_level is RiskLevel.LOW
