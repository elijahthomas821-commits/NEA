"""Deal rules: every gate, the tiers, the caps and the safety properties."""

from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.analysis.authenticity.risk import AuthenticityAssessment, Signal
from app.analysis.deals.engine import DealInputs, ExposureSnapshot, decide
from app.analysis.pricing.estimates import PriceEstimate
from app.analysis.profit.model import profit_breakdown
from app.analysis.velocity.velocity import VelocityResult
from app.config.loader import load_default_config
from app.config.schemas import DealRulesConfig
from app.core.enums import CompLevel, ConfigKind, Decision, ListingStatus, RiskLevel

D = Decimal
RULES: DealRulesConfig = load_default_config(ConfigKind.DEAL_RULES)  # type: ignore[assignment]
FEES = load_default_config(ConfigKind.FEES)


def estimate(**overrides) -> PriceEstimate:
    data = {
        "basis": "comps",
        "currency": "GBP",
        "quick": D("95"),
        "expected": D("110"),
        "optimistic": D("125"),
        "confidence": D("0.8"),
        "level": CompLevel.L2,
        "sample_size": 12,
        "effective_sample_size": D("10"),
        "p10": D("80"),
        "p25": D("95"),
    }
    data.update(overrides)
    return PriceEstimate(**data)


def auth(risk="0.10", confidence="0.70", warning=False, signals=None) -> AuthenticityAssessment:
    return AuthenticityAssessment(
        risk_score=D(risk),
        risk_level=RiskLevel.LOW,
        confidence=D(confidence),
        signals=signals or ([Signal(code="X", shift=D("2.0"), detail="x")] if warning else []),
    )


def inputs(**overrides) -> DealInputs:
    price = overrides.pop("price", D("45.00"))
    est = overrides.pop("estimate", estimate())
    data = {
        "listing_status": ListingStatus.ACTIVE,
        "price": price,
        "currency": "GBP",
        "brand_known": True,
        "category_known": True,
        "category_in_scope": True,
        "product_is_specific": True,
        "product_confidence": D("0.9"),
        "estimate": est,
        "profit": profit_breakdown(price, est.expected, FEES)
        if price is not None and est
        else None,
        "velocity": VelocityResult(median_days_to_sale=D(9), liquidity_score=D("0.8")),
        "authenticity": auth(),
    }
    data.update(overrides)
    return DealInputs(**data)


def test_good_deal_is_high_priority():
    result = decide(inputs(), RULES)
    assert result.decision is Decision.HIGH_PRIORITY, result.reasons
    assert result.gate_failures == []


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"listing_status": ListingStatus.SOLD}, "LISTING_NOT_ACTIVE"),
        ({"price": None}, "MISSING_PRICE"),
        ({"currency": "EUR"}, "CURRENCY_UNSUPPORTED"),
        ({"brand_known": False}, "BRAND_UNKNOWN"),
        ({"category_known": False}, "CATEGORY_UNKNOWN"),
        ({"category_in_scope": False}, "CATEGORY_OUT_OF_SCOPE"),
        ({"is_kids": True}, "KIDS_SIZE"),
        ({"replica_terms": ["replica"]}, "REPLICA_LANGUAGE"),
        ({"estimate": None, "profit": None}, "INSUFFICIENT_MARKET_DATA"),
        ({"price": D("90.00")}, "PROFIT_BELOW_MIN"),
        ({"product_confidence": D("0.3")}, "PRODUCT_CONFIDENCE_LOW"),
        ({"authenticity": auth(risk="0.6", warning=True)}, "AUTH_RISK_HIGH"),
        ({"velocity": VelocityResult(median_days_to_sale=D(90))}, "SALE_TOO_SLOW"),
        ({"price": D("350"), "estimate": estimate(expected=D("900"))}, "PRICE_ABOVE_CAP"),
        ({"exposure": ExposureSnapshot(unsold_cost=D("1990"))}, "INVENTORY_EXPOSURE_EXCEEDED"),
        ({"exposure": ExposureSnapshot(units_of_product=3)}, "UNITS_PER_PRODUCT_EXCEEDED"),
        (
            {
                "authenticity": auth(
                    signals=[Signal(code="SELLER_BLOCKED", shift=D(10), detail="b")]
                )
            },
            "SELLER_BLOCKED",
        ),
    ],
)
def test_each_gate_rejects(overrides, code):
    result = decide(inputs(**overrides), RULES)
    assert result.decision is Decision.REJECTED, result.reasons
    assert code in result.codes


def test_capital_per_item_gate():
    rules = RULES.model_copy(update={"max_capital_per_item": D("40")})
    assert "CAPITAL_PER_ITEM_EXCEEDED" in decide(inputs(), rules).codes


def test_roi_gate():
    # Buy £200, sell £260: profit £40.61 clears £25, but ROI 19% misses 30% by far.
    result = decide(inputs(price=D("200"), estimate=estimate(expected=D("260"))), RULES)
    assert result.decision is Decision.REJECTED
    assert "ROI_BELOW_MIN" in result.codes
    assert "PROFIT_BELOW_MIN" not in result.codes


def test_near_miss_goes_to_review():
    # Profit £23.34 against a £25 minimum (within 10%).
    result = decide(inputs(price=D("76.50")), RULES)
    assert result.decision is Decision.REVIEW
    assert {"PROFIT_BELOW_MIN", "NEAR_MISS"} <= set(result.codes)


def test_far_miss_is_rejected():
    assert decide(inputs(price=D("85")), RULES).decision is Decision.REJECTED


def test_near_miss_plus_categorical_failure_is_rejected():
    result = decide(inputs(price=D("76.50"), is_kids=True), RULES)
    assert result.decision is Decision.REJECTED


def test_review_disabled():
    rules = RULES.model_copy(update={"review": RULES.review.model_copy(update={"enabled": False})})
    assert decide(inputs(price=D("76.50")), rules).decision is Decision.REJECTED


class TestTierLimits:
    @pytest.mark.parametrize(
        ("overrides", "code"),
        [
            ({"product_confidence": D("0.8")}, "NOT_HIGH_PRODUCT_CONFIDENCE"),
            ({"authenticity": auth(risk="0.30")}, "NOT_HIGH_AUTH_RISK"),
            ({"estimate": estimate(confidence=D("0.5"))}, "NOT_HIGH_ESTIMATE_CONFIDENCE"),
            ({"estimate": estimate(level=CompLevel.L5)}, "BROAD_COMP_LEVEL"),
            ({"estimate": estimate(effective_sample_size=D("6"))}, "LOW_EFFECTIVE_N"),
            ({"damage_terms": ["hole"]}, "DAMAGE_MENTIONED"),
            ({"possible_duplicate": True}, "POSSIBLE_RELIST"),
            (
                {
                    "authenticity": auth(
                        signals=[Signal(code="PRICE_ANOMALY_SEVERE", shift=D("2"), detail="p")]
                    )
                },
                "PRICE_ANOMALY",
            ),
        ],
    )
    def test_normal_not_high(self, overrides, code):
        result = decide(inputs(**overrides), RULES)
        assert result.decision is Decision.NORMAL, result.reasons
        assert code in result.codes

    def test_price_guide_capped_at_review(self):
        result = decide(
            inputs(estimate=estimate(basis="price_guide", level=CompLevel.GUIDE)), RULES
        )
        assert result.decision is Decision.REVIEW
        assert "ESTIMATE_FROM_PRICE_GUIDE" in result.codes

    def test_mislabel_capped_at_normal(self):
        result = decide(inputs(mislabel=True), RULES)
        assert result.decision is Decision.NORMAL
        assert "MISLABEL_DERIVED" in result.codes

    def test_ai_unavailable_capped(self):
        assert decide(inputs(ai_unavailable_but_needed=True), RULES).decision is Decision.NORMAL

    def test_velocity_unknown_capped(self):
        result = decide(inputs(velocity=VelocityResult()), RULES)
        assert result.decision is Decision.NORMAL
        assert "VELOCITY_UNKNOWN" in result.codes

    def test_velocity_can_be_required(self):
        rules = RULES.model_copy(update={"require_velocity_data": True})
        assert decide(inputs(velocity=VelocityResult()), rules).decision is Decision.REJECTED

    def test_contradictions_go_to_review(self):
        result = decide(inputs(contradictions=["size field says M; title says L"]), RULES)
        assert result.decision is Decision.REVIEW
        assert "CONTRADICTORY_DETAILS" in result.codes


class TestAuthenticityRouting:
    def test_prior_only_high_risk_asks_for_evidence(self):
        result = decide(inputs(authenticity=auth(risk="0.45")), RULES)
        assert result.decision is Decision.REVIEW
        assert "AUTH_NEEDS_EVIDENCE" in result.codes
        assert "AUTH_RISK_HIGH" not in result.codes

    def test_weak_warning_signs_ask_for_evidence(self):
        weak = [Signal(code="PRICE_ANOMALY_MODERATE", shift=D("0.8"), detail="lowish price")]
        result = decide(inputs(authenticity=auth(risk="0.55", signals=weak)), RULES)
        assert result.decision is Decision.REVIEW
        assert "AUTH_NEEDS_EVIDENCE" in result.codes

    def test_low_confidence_asks_for_photos(self):
        result = decide(inputs(authenticity=auth(confidence="0.30")), RULES)
        assert result.decision is Decision.REVIEW
        assert "AUTH_NEEDS_EVIDENCE" in result.codes

    def test_low_confidence_can_reject(self):
        rules = RULES.model_copy(update={"low_auth_confidence_action": "reject"})
        result = decide(inputs(authenticity=auth(confidence="0.30")), rules)
        assert result.decision is Decision.REJECTED
        assert "AUTH_CONFIDENCE_LOW" in result.codes


@given(risk=st.decimals(min_value="0.251", max_value=1, places=3), warning=st.booleans())
def test_high_risk_is_never_high_priority(risk, warning):
    result = decide(inputs(authenticity=auth(risk=str(risk), warning=warning)), RULES)
    assert result.decision is not Decision.HIGH_PRIORITY


@given(
    confidence=st.decimals(min_value="0.5", max_value="0.99", places=2),
    risk=st.decimals(min_value=0, max_value="0.25", places=3),
)
def test_mislabel_is_never_high_priority(confidence, risk):
    result = decide(
        inputs(mislabel=True, product_confidence=confidence, authenticity=auth(risk=str(risk))),
        RULES,
    )
    assert result.decision is not Decision.HIGH_PRIORITY


@given(st.decimals(min_value="0.01", max_value=1000, places=2))
def test_rejected_listings_always_explain_why(price):
    result = decide(inputs(price=price), RULES)
    if result.decision is Decision.REJECTED:
        assert result.gate_failures
        assert all(r.detail for r in result.reasons)


def test_price_guide_estimate_never_high_priority():
    for level in (CompLevel.GUIDE,):
        result = decide(inputs(estimate=estimate(basis="price_guide", level=level)), RULES)
        assert result.decision is not Decision.HIGH_PRIORITY
