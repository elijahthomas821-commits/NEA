"""Deterministic authenticity risk scoring (log-odds model).

The score starts from the brand's base risk (the prior share of counterfeits for that brand on
second-hand marketplaces) and every signal shifts the odds:

    logit(risk) = logit(base_risk) + Σ shift_i          risk = 1 / (1 + e^(−logit))

Suspicious signals (price far below comps, replica wording, reused photos, a brand-new seller)
have positive shifts; good evidence (badge and labels seen in the photos, an established or
trusted seller, a normal price) has negative shifts, so evidence can lower the risk below the
prior. AI photo inspection (when enabled) only reports per-checklist-item observations; the
score is computed here from configured shifts. Confidence reflects how much could actually be
checked (photos, checklist items seen, seller information, market data).
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.normalisation.text import find_phrase, normalise_text, tokenise
from app.config.schemas import AuthenticityConfig
from app.core.enums import CheckResult, RiskLevel

ONE = Decimal(1)
ZERO = Decimal(0)


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class SellerSignals(Frozen):
    rating: Decimal | None = None
    review_count: int | None = None
    member_since: date | None = None
    operator_flag: str = "none"  # none | trusted | blocked


class ChecklistObservation(Frozen):
    code: str
    result: CheckResult
    note: str = ""


class AuthenticityInputs(Frozen):
    brand_slug: str | None
    brand_base_risk: Decimal
    price: Decimal | None = None
    comps_median: Decimal | None = None
    text: str = ""
    replica_terms: list[str] = Field(default_factory=list)
    seller: SellerSignals | None = None
    photo_count: int = 0
    reused_photo_matches: int = 0
    mislabel: bool = False
    contradiction_count: int = 0
    checklist: list[ChecklistObservation] = Field(default_factory=list)
    photo_quality: str | None = None
    ai_concerns: list[str] = Field(default_factory=list)
    as_of: date


class Signal(Frozen):
    code: str
    shift: Decimal  # log-odds; positive raises risk, negative lowers it
    detail: str


class AuthenticityAssessment(Frozen):
    risk_score: Decimal
    risk_level: RiskLevel
    confidence: Decimal
    signals: list[Signal] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    concerns: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)

    @property
    def price_anomaly(self) -> bool:
        """A severe under-pricing flag (too good to be true)."""
        return any(s.code == "PRICE_ANOMALY_SEVERE" for s in self.signals)

    @property
    def has_warning_signs(self) -> bool:
        """True if any evidence (not just the brand prior) raised the risk."""
        return any(s.shift > 0 for s in self.signals)

    @property
    def warning_strength(self) -> Decimal:
        """Total log-odds added by warning signs."""
        return sum((s.shift for s in self.signals if s.shift > 0), Decimal(0))


def _phrases_present(text: str, phrases: list[str]) -> list[str]:
    tokens = tokenise(text)
    found = []
    for phrase in phrases:
        if find_phrase(tokens, normalise_text(phrase).split()):
            found.append(phrase)
    return found


def risk_level(score: Decimal, cfg: AuthenticityConfig) -> RiskLevel:
    if score < cfg.low_risk_below:
        return RiskLevel.LOW
    if score < cfg.high_risk_from:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def _logit(p: Decimal) -> Decimal:
    p = min(max(p, Decimal("0.001")), Decimal("0.999"))
    return (p / (ONE - p)).ln()


def _sigmoid(x: Decimal) -> Decimal:
    return ONE / (ONE + (-x).exp())


def assess_authenticity(
    inputs: AuthenticityInputs, cfg: AuthenticityConfig
) -> AuthenticityAssessment:
    sh = cfg.shifts
    signals: list[Signal] = []
    evidence: list[str] = []
    concerns: list[str] = []
    checks: list[str] = []

    def add(code: str, shift: Decimal, detail: str) -> None:
        signals.append(Signal(code=code, shift=shift, detail=detail))
        (concerns if shift > 0 else evidence).append(detail)

    # Price compared with comparable sales (median).
    if inputs.price is not None and inputs.comps_median is not None and inputs.comps_median > 0:
        median = inputs.comps_median.quantize(Decimal("0.01"))
        share = (inputs.price / inputs.comps_median * 100).quantize(Decimal("1"))
        if inputs.price < inputs.comps_median * cfg.severe_price_ratio_to_median:
            add(
                "PRICE_ANOMALY_SEVERE",
                sh.price_anomaly_severe,
                f"price {inputs.price} is only {share}% of what similar items sell for "
                f"(median {median}) - too good to be true?",
            )
            checks.append("Ask why the price is so low and for proof of purchase")
        elif inputs.price < inputs.comps_median * cfg.moderate_price_ratio_to_median:
            add(
                "PRICE_ANOMALY_MODERATE",
                sh.price_anomaly_moderate,
                f"price {inputs.price} is {share}% of what similar items sell for "
                f"(median {median})",
            )
        else:
            add("PRICE_NORMAL", sh.price_consistent_with_comps, "price is in the normal range")

    if inputs.replica_terms:
        add(
            "REPLICA_LANGUAGE",
            sh.replica_language,
            "listing uses replica/look-alike wording: " + ", ".join(inputs.replica_terms),
        )

    missing_tags = _phrases_present(inputs.text, cfg.missing_tag_phrases)
    if missing_tags:
        add(
            "MISSING_TAGS",
            sh.missing_tags_language,
            "mentions missing labels/tags: " + ", ".join(missing_tags),
        )
        checks.append("Ask for photos of whatever labels remain")

    seller = inputs.seller
    if seller is not None:
        if seller.operator_flag == "blocked":
            add("SELLER_BLOCKED", Decimal(10), "you have blocked this seller")
        if seller.operator_flag == "trusted":
            add("SELLER_TRUSTED", sh.trusted_seller, "you marked this seller as trusted")
        new = seller.member_since is not None and (
            (inputs.as_of - seller.member_since).days < cfg.new_account_days
        )
        if new:
            add("SELLER_NEW_ACCOUNT", sh.seller_new_account, "seller account is very new")
        if seller.review_count is not None and seller.review_count < cfg.few_reviews_below:
            add(
                "SELLER_FEW_REVIEWS",
                sh.seller_few_reviews,
                f"seller has only {seller.review_count} reviews",
            )
        if seller.rating is not None and seller.rating < cfg.low_rating_below:
            add("SELLER_LOW_RATING", sh.seller_low_rating, f"seller rating is {seller.rating}")
        established = (
            seller.review_count is not None
            and seller.review_count >= cfg.established_min_reviews
            and (seller.rating or ZERO) >= cfg.established_min_rating
        )
        if established:
            add(
                "SELLER_ESTABLISHED",
                sh.established_seller,
                f"established seller ({seller.review_count} reviews, rated {seller.rating})",
            )

    if inputs.reused_photo_matches:
        add(
            "REUSED_PHOTOS",
            sh.reused_photos_other_seller,
            "the same photo appears on another seller's listing (stock or stolen images)",
        )
        checks.append("Ask for a photo with a note showing the seller's username and today's date")
    if inputs.mislabel:
        add(
            "MISLABEL_DERIVED",
            sh.mislabel_derived,
            "brand inferred from photos of an unbranded listing",
        )
    if inputs.contradiction_count:
        add(
            "CONTRADICTORY_DETAILS",
            sh.contradictory_identification,
            "the listing's details contradict each other",
        )

    # Photo checklist (observations from AI photo inspection, when available).
    items = {i.code: i for i in cfg.brand_checklists.get(inputs.brand_slug or "", [])}
    observed = 0
    seen: set[str] = set()
    for obs in inputs.checklist:
        item = items.get(obs.code)
        if item is None:
            continue
        seen.add(obs.code)
        note = f" ({obs.note})" if obs.note else ""
        if obs.result == CheckResult.OBSERVED:
            observed += 1
            add(f"CHECK_OBSERVED_{obs.code.upper()}", item.observed_shift,
                f"photos show: {item.description}{note}")  # fmt: skip
        elif obs.result == CheckResult.CONCERN:
            add(f"CHECK_CONCERN_{obs.code.upper()}", item.concern_shift,
                f"questionable in photos: {item.description}{note}")  # fmt: skip
            if item.recommended_check:
                checks.append(item.recommended_check)
        elif item.recommended_check:
            checks.append(item.recommended_check)
    for code, item in items.items():
        if code not in seen and item.recommended_check:
            checks.append(item.recommended_check)
    evidence.extend(f"photo note: {c}" for c in inputs.ai_concerns)

    logit = _logit(inputs.brand_base_risk) + sum((s.shift for s in signals), ZERO)
    risk = _sigmoid(logit).quantize(Decimal("0.001"))

    # Confidence: how much could actually be checked.
    c = cfg.confidence
    confidence = c.base + min(c.per_photo * inputs.photo_count, c.max_photo_bonus)
    confidence += c.per_observed_check * observed
    if seller is not None and (seller.review_count is not None or seller.rating is not None):
        confidence += c.seller_info_bonus
    if inputs.comps_median is not None:
        confidence += c.comps_bonus
    if inputs.photo_quality == "poor":
        confidence -= c.per_photo * 2
    confidence = min(confidence, c.maximum)
    if inputs.photo_count == 0:
        confidence = min(confidence, c.no_photos_cap)
        checks.insert(0, "Ask the seller for more photos (labels, tags, badge, hardware)")
    confidence = max(confidence, ZERO).quantize(Decimal("0.001"))

    checks.extend(cfg.generic_recommended_checks)
    return AuthenticityAssessment(
        risk_score=risk,
        risk_level=risk_level(risk, cfg),
        confidence=confidence,
        signals=signals,
        evidence=evidence,
        concerns=concerns,
        recommended_checks=list(dict.fromkeys(checks)),
    )
