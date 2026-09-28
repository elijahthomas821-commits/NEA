"""The deal rule engine.

1. **Hard gates** — any failure rejects the listing, with a reason code for each failure.
2. **Review** — if every failure is a narrow numeric miss (within ``review.near_miss_pct`` of
   its threshold), the listing goes to REVIEW instead of being rejected.
3. **Tiers** — a listing that passes every gate is HIGH priority only if it also meets the
   stricter ``high_priority`` thresholds and none of the limiting conditions apply; otherwise
   NORMAL. Caps then limit the best reachable tier (mislabelled, priced from your guide, AI
   needed but unavailable, unknown sale speed, contradictory details).

The engine never decides to buy anything; it labels listings for you.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.authenticity.risk import AuthenticityAssessment
from app.analysis.pricing.estimates import PriceEstimate
from app.analysis.profit.max_price import MaxPriceResult
from app.analysis.profit.model import ProfitBreakdown
from app.analysis.velocity.velocity import VelocityResult
from app.config.schemas import DealRulesConfig
from app.core.enums import CompLevel, Decision, ListingStatus

ReasonKind = Literal["gate", "limit", "info"]
ONE = Decimal(1)
# Gates that may be "near misses" (numeric thresholds) rather than categorical failures.
NEAR_MISS_CAPABLE = {
    "PROFIT_BELOW_MIN",
    "ROI_BELOW_MIN",
    "PRODUCT_CONFIDENCE_LOW",
    "SALE_TOO_SLOW",
}


class Reason(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    kind: ReasonKind
    detail: str
    near_miss: bool = False


class ExposureSnapshot(BaseModel):
    """Money already tied up in unsold stock."""

    model_config = ConfigDict(frozen=True)

    unsold_cost: Decimal = Decimal(0)
    units_of_product: int = 0


class DealInputs(BaseModel):
    model_config = ConfigDict(frozen=True)

    listing_status: ListingStatus
    price: Decimal | None
    currency: str | None
    brand_known: bool
    category_known: bool
    category_in_scope: bool | None
    is_kids: bool = False
    replica_terms: list[str] = Field(default_factory=list)
    damage_terms: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    mislabel: bool = False
    product_is_specific: bool = False
    product_confidence: Decimal = Decimal(0)
    estimate: PriceEstimate | None = None
    profit: ProfitBreakdown | None = None
    max_price: MaxPriceResult | None = None
    velocity: VelocityResult = Field(default_factory=VelocityResult)
    authenticity: AuthenticityAssessment | None = None
    exposure: ExposureSnapshot = Field(default_factory=ExposureSnapshot)
    ai_unavailable_but_needed: bool = False
    possible_duplicate: bool = False


class DealDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    reasons: list[Reason]

    @property
    def codes(self) -> list[str]:
        return [r.code for r in self.reasons]

    @property
    def gate_failures(self) -> list[Reason]:
        return [r for r in self.reasons if r.kind == "gate"]


def _near(value: Decimal, threshold: Decimal, pct: Decimal, *, higher_is_better: bool) -> bool:
    """Within ``pct`` of the threshold on the wrong side."""
    if threshold == 0:
        return False
    if higher_is_better:
        return value >= threshold * (ONE - pct)
    return value <= threshold * (ONE + pct)


def _cap(decision: Decision, cap: Decision) -> Decision:
    return cap if decision.rank > cap.rank else decision


def decide(inputs: DealInputs, rules: DealRulesConfig) -> DealDecision:
    reasons: list[Reason] = []
    near_pct = rules.review.near_miss_pct

    def gate(code: str, detail: str, *, near_miss: bool = False) -> None:
        reasons.append(Reason(code=code, kind="gate", detail=detail, near_miss=near_miss))

    def limit(code: str, detail: str) -> None:
        reasons.append(Reason(code=code, kind="limit", detail=detail))

    # ---------------------------------------------------------------- categorical gates
    if inputs.listing_status not in (ListingStatus.ACTIVE, ListingStatus.RESERVED):
        gate("LISTING_NOT_ACTIVE", f"listing is {inputs.listing_status.value}")
    if inputs.price is None:
        gate("MISSING_PRICE", "no price recorded for the listing")
    elif inputs.currency != rules.currency:
        gate(
            "CURRENCY_UNSUPPORTED",
            f"listing is in {inputs.currency}; rules are in {rules.currency}",
        )
    if not inputs.brand_known:
        gate("BRAND_UNKNOWN", "brand not identified or not in the catalogue")
    if not inputs.category_known:
        gate("CATEGORY_UNKNOWN", "category not identified")
    elif inputs.category_in_scope is False:
        gate("CATEGORY_OUT_OF_SCOPE", "category is not one you resell")
    if inputs.is_kids and rules.exclude_kids_sizes:
        gate("KIDS_SIZE", "children's size")
    if inputs.replica_terms:
        gate("REPLICA_LANGUAGE", "replica/look-alike wording: " + ", ".join(inputs.replica_terms))

    auth = inputs.authenticity
    if auth is not None and any(s.code == "SELLER_BLOCKED" for s in auth.signals):
        gate("SELLER_BLOCKED", "you blocked this seller")

    # ---------------------------------------------------------------- market & money gates
    estimate = inputs.estimate
    profit = inputs.profit
    if estimate is None:
        if inputs.brand_known and inputs.category_known and inputs.category_in_scope is not False:
            gate(
                "INSUFFICIENT_MARKET_DATA",
                "not enough comparable sales (and no price guide entry) to estimate a resale price",
            )
    elif profit is not None and inputs.price is not None:
        net_profit = profit.net_profit
        if net_profit < rules.min_profit:
            gate(
                "PROFIT_BELOW_MIN",
                f"expected profit {net_profit} < minimum {rules.min_profit}",
                near_miss=_near(net_profit, rules.min_profit, near_pct, higher_is_better=True),
            )
        roi = profit.roi
        if rules.min_roi is not None and roi is not None and roi < rules.min_roi:
            gate(
                "ROI_BELOW_MIN",
                f"expected ROI {roi:.1%} < minimum {rules.min_roi:.0%}",
                near_miss=_near(roi, rules.min_roi, near_pct, higher_is_better=True),
            )
        total = profit.acquisition.total
        if total > rules.max_capital_per_item:
            gate("CAPITAL_PER_ITEM_EXCEEDED", f"total cost {total} > {rules.max_capital_per_item}")
        if inputs.exposure.unsold_cost + total > rules.max_inventory_exposure:
            gate(
                "INVENTORY_EXPOSURE_EXCEEDED",
                f"unsold stock {inputs.exposure.unsold_cost} + {total} "
                f"> limit {rules.max_inventory_exposure}",
            )
    if inputs.price is not None and inputs.price > rules.max_purchase_price:
        gate("PRICE_ABOVE_CAP", f"price {inputs.price} > cap {rules.max_purchase_price}")
    if (
        inputs.product_is_specific
        and inputs.exposure.units_of_product >= rules.max_units_per_product
    ):
        gate(
            "UNITS_PER_PRODUCT_EXCEEDED",
            f"you already hold {inputs.exposure.units_of_product} unsold of this product",
        )

    # ---------------------------------------------------------------- confidence gates
    if inputs.brand_known and inputs.product_confidence < rules.min_product_confidence:
        gate(
            "PRODUCT_CONFIDENCE_LOW",
            f"identification confidence {inputs.product_confidence} "
            f"< {rules.min_product_confidence}",
            near_miss=_near(
                inputs.product_confidence, rules.min_product_confidence, near_pct,
                higher_is_better=True,
            ),
        )  # fmt: skip
    needs_evidence: list[str] = []
    if auth is not None:
        if auth.risk_score > rules.max_authenticity_risk:
            detail = f"counterfeit risk {auth.risk_score} > {rules.max_authenticity_risk}"
            if auth.warning_strength >= rules.auth_reject_min_warning:
                gate("AUTH_RISK_HIGH", detail)
            else:
                # Mostly the brand's prior (plus weak signs at most): ask for evidence.
                needs_evidence.append(f"{detail}, mostly the brand's base risk")
        if auth.confidence < rules.min_authenticity_confidence:
            detail = (
                f"authenticity check confidence {auth.confidence} "
                f"< {rules.min_authenticity_confidence}: need more photos or seller details"
            )
            if rules.low_auth_confidence_action == "reject":
                gate("AUTH_CONFIDENCE_LOW", detail)
            else:
                needs_evidence.append(detail)

    # ---------------------------------------------------------------- velocity
    velocity = inputs.velocity
    if velocity.median_days_to_sale is not None and rules.max_median_sale_days is not None:
        limit_days = Decimal(rules.max_median_sale_days)
        if velocity.median_days_to_sale > limit_days:
            gate(
                "SALE_TOO_SLOW",
                f"median {velocity.median_days_to_sale} days to sell "
                f"> {rules.max_median_sale_days}",
                near_miss=_near(
                    velocity.median_days_to_sale, limit_days, near_pct, higher_is_better=False
                ),
            )
    elif velocity.median_days_to_sale is None and rules.require_velocity_data:
        gate("VELOCITY_UNKNOWN", "no sale-speed data")

    # ---------------------------------------------------------------- decision
    gates = [r for r in reasons if r.kind == "gate"]
    if gates:
        all_near = all(r.near_miss and r.code in NEAR_MISS_CAPABLE for r in gates)
        if rules.review.enabled and all_near:
            reasons.append(
                Reason(code="NEAR_MISS", kind="info", detail="narrowly misses your thresholds")
            )
            return DealDecision(decision=Decision.REVIEW, reasons=reasons)
        return DealDecision(decision=Decision.REJECTED, reasons=reasons)

    decision = _tier(inputs, rules, limit)
    caps = rules.caps
    if inputs.mislabel:
        limit("MISLABEL_DERIVED", "brand inferred from photos, not stated by the seller")
        decision = _cap(decision, caps.mislabel)
    if estimate is not None and estimate.basis == "price_guide":
        limit("ESTIMATE_FROM_PRICE_GUIDE", "priced from your price guide, not sales data")
        decision = _cap(decision, caps.price_guide)
    if inputs.ai_unavailable_but_needed:
        limit("AI_UNAVAILABLE", "identification needed AI help, which was unavailable")
        decision = _cap(decision, caps.ai_unavailable)
    if velocity.median_days_to_sale is None:
        limit("VELOCITY_UNKNOWN", "no sale-speed data")
        decision = _cap(decision, caps.velocity_unknown)
    if needs_evidence:
        limit("AUTH_NEEDS_EVIDENCE", "; ".join(needs_evidence))
        decision = _cap(decision, Decision.REVIEW)
    if inputs.contradictions and rules.review.enabled and rules.review.on_contradiction:
        limit("CONTRADICTORY_DETAILS", "; ".join(inputs.contradictions))
        decision = _cap(decision, Decision.REVIEW)
    return DealDecision(decision=decision, reasons=reasons)


def _tier(
    inputs: DealInputs, rules: DealRulesConfig, limit: Callable[[str, str], None]
) -> Decision:
    """HIGH if every stricter condition holds; otherwise NORMAL (recording what failed)."""
    hp = rules.high_priority
    failures: list[tuple[str, str]] = []
    estimate = inputs.estimate
    auth = inputs.authenticity
    if inputs.product_confidence < hp.min_product_confidence:
        failures.append(
            ("NOT_HIGH_PRODUCT_CONFIDENCE", f"identification {inputs.product_confidence}")
        )
    if auth is not None and auth.risk_score > hp.max_authenticity_risk:
        failures.append(("NOT_HIGH_AUTH_RISK", f"counterfeit risk {auth.risk_score}"))
    if auth is not None and auth.price_anomaly:
        failures.append(("PRICE_ANOMALY", "price is a small fraction of comparable sales"))
    if estimate is not None:
        if estimate.confidence < hp.min_estimate_confidence:
            failures.append(
                ("NOT_HIGH_ESTIMATE_CONFIDENCE", f"estimate confidence {estimate.confidence}")
            )
        if estimate.level != CompLevel.GUIDE and estimate.level.rank > hp.max_comp_level.rank:
            failures.append(
                (
                    "BROAD_COMP_LEVEL",
                    f"priced at {estimate.level.value} ({estimate.level.description})",
                )
            )
        if estimate.effective_sample_size < hp.min_effective_n:
            failures.append(
                (
                    "LOW_EFFECTIVE_N",
                    f"effective sample {estimate.effective_sample_size.quantize(Decimal('0.1'))}",
                )
            )
    profit = inputs.profit
    if hp.min_profit is not None and profit is not None and profit.net_profit < hp.min_profit:
        failures.append(("NOT_HIGH_PROFIT", f"profit {profit.net_profit}"))
    if hp.min_roi is not None and profit is not None and (profit.roi or 0) < hp.min_roi:
        failures.append(("NOT_HIGH_ROI", "ROI below the high-priority minimum"))
    liquidity = inputs.velocity.liquidity_score
    if hp.min_liquidity is not None and (liquidity is None or liquidity < hp.min_liquidity):
        failures.append(("NOT_HIGH_LIQUIDITY", f"liquidity {liquidity}"))
    if inputs.damage_terms:
        failures.append(("DAMAGE_MENTIONED", "listing mentions: " + ", ".join(inputs.damage_terms)))
    if inputs.possible_duplicate:
        failures.append(("POSSIBLE_RELIST", "looks like a re-listing of an item seen before"))
    for code, detail in failures:
        limit(code, detail)
    return Decision.NORMAL if failures else Decision.HIGH_PRIORITY
