"""Versioned business configuration schemas.

Every assumption the analysis makes (fees, multipliers, thresholds, weights) lives in one of
these models. Payloads are stored in ``config_versions`` as JSON; editing creates a new version
so that every past evaluation can be reproduced with the exact configuration it used.

All models forbid unknown keys, so a typo in a threshold name fails loudly instead of silently
falling back to a default.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.enums import CompLevel, Condition, ConfigKind, Decision, SaleSource

Ratio = Annotated[Decimal, Field(ge=0, le=1)]
PositiveMoney = Annotated[Decimal, Field(ge=0, max_digits=12, decimal_places=2)]
Multiplier = Annotated[Decimal, Field(gt=0, le=5)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- conditions


class ConditionsConfig(StrictModel):
    """Relative value of each condition grade (``very_good`` = 1.00 by convention)."""

    multipliers: dict[Condition, Multiplier]
    # Comps whose condition is unknown are treated as this grade (and down-weighted by market
    # config ``unknown_condition_weight``).
    assume_when_unknown: Condition = Condition.GOOD

    @field_validator("multipliers")
    @classmethod
    def _all_grades(cls, value: dict[Condition, Decimal]) -> dict[Condition, Decimal]:
        missing = set(Condition) - set(value)
        if missing:
            raise ValueError(f"missing multipliers for: {sorted(m.value for m in missing)}")
        return value


# --------------------------------------------------------------------------- sizes

LETTER_SCALE: tuple[str, ...] = ("XXS", "XS", "S", "M", "L", "XL", "XXL", "3XL", "4XL")


class SizesConfig(StrictModel):
    """Size systems and value multipliers.

    ``numeric_systems`` maps a numeric size system to letter sizes, e.g. Italian/EU jacket
    sizes (``48`` → ``M``) or Moncler's ``0``-``7`` scale. ``brand_numeric_system`` says which
    system a bare number means for a brand when the listing does not say.
    """

    numeric_systems: dict[str, dict[str, str]]
    brand_numeric_system: dict[str, str] = Field(default_factory=dict)
    default_numeric_system: str | None = None
    # Value multipliers by size, per category slug; ``default`` applies otherwise.
    multipliers: dict[str, dict[str, Multiplier]]

    @model_validator(mode="after")
    def _validate(self) -> SizesConfig:
        for system, mapping in self.numeric_systems.items():
            for letter in mapping.values():
                if letter not in LETTER_SCALE:
                    raise ValueError(f"{system}: unknown letter size {letter!r}")
        for brand, system in self.brand_numeric_system.items():
            if system not in self.numeric_systems:
                raise ValueError(f"brand {brand!r} uses unknown size system {system!r}")
        if self.default_numeric_system and self.default_numeric_system not in self.numeric_systems:
            raise ValueError("default_numeric_system is not defined")
        if "default" not in self.multipliers:
            raise ValueError("multipliers must include a 'default' table")
        for table in self.multipliers.values():
            for size in table:
                if size not in LETTER_SCALE:
                    raise ValueError(f"multiplier for unknown size {size!r}")
        return self


# --------------------------------------------------------------------------- market


class EstimatePercentiles(StrictModel):
    quick: Annotated[Decimal, Field(ge=1, le=99)] = Decimal(25)
    expected: Annotated[Decimal, Field(ge=1, le=99)] = Decimal(50)
    optimistic: Annotated[Decimal, Field(ge=1, le=99)] = Decimal(75)

    @model_validator(mode="after")
    def _ordered(self) -> EstimatePercentiles:
        if not self.quick <= self.expected <= self.optimistic:
            raise ValueError("percentiles must satisfy quick <= expected <= optimistic")
        return self


class LastAskingPriceRules(StrictModel):
    """How to treat 'sold' listings where only the last asking price is known.

    On Vinted a sold item shows its last asking price; accepted offers are private, so the
    real sale price is at or below it. With no final-price data available these observations
    are still the best evidence, so by default they are used with a price haircut and reduced
    trust. Set ``use_for_price`` to false to use them for sale velocity only.
    """

    use_for_price: bool = True
    haircut: Annotated[Decimal, Field(gt=0, le=1)] = Decimal("0.92")
    trust_multiplier: Ratio = Decimal("0.6")


class OutlierRules(StrictModel):
    min_n: int = Field(default=4, ge=3)
    iqr_min_n: int = Field(default=8, ge=4)
    iqr_k: Annotated[Decimal, Field(gt=0)] = Decimal("1.5")
    mad_k: Annotated[Decimal, Field(gt=0)] = Decimal("3.0")


ConfidenceFactor = Literal["n", "level", "dispersion", "recency", "match"]


def _default_factor_weights() -> dict[ConfidenceFactor, Decimal]:
    return {
        "n": Decimal(1),
        "level": Decimal(1),
        "dispersion": Decimal(1),
        "recency": Decimal("0.5"),
        "match": Decimal(1),
    }


class ConfidenceRules(StrictModel):
    n_scale: Annotated[Decimal, Field(gt=0)] = Decimal(5)
    dispersion_scale: Annotated[Decimal, Field(gt=0)] = Decimal("0.5")
    level_factors: dict[CompLevel, Ratio] = Field(
        default_factory=lambda: {
            CompLevel.L1: Decimal("1.00"),
            CompLevel.L2: Decimal("0.95"),
            CompLevel.L3: Decimal("0.85"),
            CompLevel.L4: Decimal("0.75"),
            CompLevel.L5: Decimal("0.55"),
            CompLevel.L6: Decimal("0.45"),
            CompLevel.GUIDE: Decimal("0.25"),
        }
    )
    factor_weights: dict[ConfidenceFactor, Decimal] = Field(default_factory=_default_factor_weights)


class VelocityRules(StrictModel):
    min_events: int = Field(default=3, ge=1)
    target_days: int = Field(default=30, ge=1)
    volume_scale: Annotated[Decimal, Field(gt=0)] = Decimal(10)
    speed_weight: Ratio = Decimal("0.6")
    high_liquidity_from: Ratio = Decimal("0.66")
    medium_liquidity_from: Ratio = Decimal("0.33")


class PriceGuideRules(StrictModel):
    enabled: bool = True
    confidence: Ratio = Decimal("0.25")


class MarketConfig(StrictModel):
    window_days: int = Field(default=365, ge=7, le=3650)
    half_life_days: Annotated[Decimal, Field(gt=0)] = Decimal(90)
    min_effective_n: Annotated[Decimal, Field(ge=1)] = Decimal(5)
    min_sample_size: int = Field(default=3, ge=1)
    levels: list[CompLevel] = Field(
        default_factory=lambda: [
            CompLevel.L1,
            CompLevel.L2,
            CompLevel.L3,
            CompLevel.L4,
            CompLevel.L5,
            CompLevel.L6,
        ]
    )
    estimate_percentiles: EstimatePercentiles = Field(default_factory=EstimatePercentiles)
    source_trust: dict[SaleSource, Ratio] = Field(
        default_factory=lambda: {
            SaleSource.OWN_SALE: Decimal("1.0"),
            SaleSource.MANUAL_ENTRY: Decimal("0.8"),
            SaleSource.CSV_IMPORT: Decimal("0.8"),
            SaleSource.OBSERVED_SOLD_LISTING: Decimal("0.7"),
            SaleSource.LICENSED_API: Decimal("0.9"),
        }
    )
    marketplace_trust: dict[str, Ratio] = Field(
        default_factory=lambda: {"vinted": Decimal("1.0"), "default": Decimal("0.8")}
    )
    last_asking_price: LastAskingPriceRules = Field(default_factory=LastAskingPriceRules)
    unknown_condition_weight: Ratio = Decimal("0.8")
    outliers: OutlierRules = Field(default_factory=OutlierRules)
    confidence: ConfidenceRules = Field(default_factory=ConfidenceRules)
    fx_max_age_days: int = Field(default=7, ge=0)
    velocity: VelocityRules = Field(default_factory=VelocityRules)
    price_guide: PriceGuideRules = Field(default_factory=PriceGuideRules)

    @field_validator("levels")
    @classmethod
    def _levels_ordered(cls, value: list[CompLevel]) -> list[CompLevel]:
        if CompLevel.GUIDE in value:
            raise ValueError("GUIDE is not a comparable-sales level; use price_guide rules")
        if not value:
            raise ValueError("at least one fallback level is required")
        ranks = [level.rank for level in value]
        if ranks != sorted(ranks) or len(set(ranks)) != len(ranks):
            raise ValueError("levels must be unique and ordered from most to least specific")
        return value

    @model_validator(mode="after")
    def _marketplace_default(self) -> MarketConfig:
        if "default" not in self.marketplace_trust:
            raise ValueError("marketplace_trust needs a 'default' entry")
        return self


# --------------------------------------------------------------------------- fees


class FeeTier(StrictModel):
    """A marginal band: ``percent`` applies to the part of the amount up to ``up_to``."""

    up_to: PositiveMoney | None = None
    percent: Ratio


class FeeRule(StrictModel):
    fixed: PositiveMoney = Decimal(0)
    percent: Ratio = Decimal(0)
    tiers: list[FeeTier] = Field(default_factory=list)
    min_fee: PositiveMoney | None = None
    max_fee: PositiveMoney | None = None

    @model_validator(mode="after")
    def _validate(self) -> FeeRule:
        if self.tiers:
            if self.percent != 0:
                raise ValueError("use either 'percent' or 'tiers', not both")
            bounds = [t.up_to for t in self.tiers]
            if any(b is None for b in bounds[:-1]):
                raise ValueError("only the last tier may be open-ended")
            finite = [b for b in bounds if b is not None]
            if finite != sorted(finite) or len(set(finite)) != len(finite):
                raise ValueError("tier bounds must be strictly increasing")
        if self.min_fee is not None and self.max_fee is not None and self.min_fee > self.max_fee:
            raise ValueError("min_fee cannot exceed max_fee")
        return self

    @property
    def is_linear(self) -> bool:
        return not self.tiers and self.min_fee is None and self.max_fee is None


class PurchaseChannel(StrictModel):
    buyer_fee: FeeRule
    default_inbound_shipping: PositiveMoney
    notes: str = ""


class SellingChannel(StrictModel):
    selling_fee: FeeRule
    outbound_shipping_paid_by_seller: PositiveMoney = Decimal(0)
    packaging_cost: PositiveMoney = Decimal(0)
    expected_refund_rate: Ratio = Decimal(0)
    other_selling_costs: PositiveMoney = Decimal(0)
    notes: str = ""


class FeesConfig(StrictModel):
    currency: str = "GBP"
    purchase_channels: dict[str, PurchaseChannel]
    selling_channels: dict[str, SellingChannel]
    default_purchase_channel: str = "vinted"
    default_selling_channel: str = "vinted"
    default_cleaning_cost: PositiveMoney = Decimal(0)
    default_repair_cost: PositiveMoney = Decimal(0)
    default_other_acquisition_cost: PositiveMoney = Decimal(0)
    values_verified_on: str | None = None

    @model_validator(mode="after")
    def _defaults_exist(self) -> FeesConfig:
        if self.default_purchase_channel not in self.purchase_channels:
            raise ValueError("default_purchase_channel is not defined")
        if self.default_selling_channel not in self.selling_channels:
            raise ValueError("default_selling_channel is not defined")
        return self


# --------------------------------------------------------------------------- deal rules


class HighPriorityRules(StrictModel):
    min_product_confidence: Ratio = Decimal("0.85")
    max_authenticity_risk: Ratio = Decimal("0.25")
    min_estimate_confidence: Ratio = Decimal("0.60")
    max_comp_level: CompLevel = CompLevel.L4
    min_effective_n: Annotated[Decimal, Field(ge=1)] = Decimal(8)
    min_profit: PositiveMoney | None = None
    min_roi: Annotated[Decimal, Field(ge=0)] | None = None
    min_liquidity: Ratio | None = None


class ReviewRules(StrictModel):
    enabled: bool = True
    near_miss_pct: Ratio = Decimal("0.10")
    on_contradiction: bool = True


class TierCaps(StrictModel):
    """The best tier a listing can reach under each limiting circumstance."""

    mislabel: Decision = Decision.NORMAL
    price_guide: Decision = Decision.REVIEW
    ai_unavailable: Decision = Decision.NORMAL
    velocity_unknown: Decision = Decision.NORMAL


class RealertRules(StrictModel):
    min_price_drop_pct: Ratio = Decimal("0.10")
    min_price_drop_abs: PositiveMoney = Decimal(5)


class DealRulesConfig(StrictModel):
    currency: str = "GBP"
    min_profit: PositiveMoney = Decimal(25)
    min_roi: Annotated[Decimal, Field(ge=0)] | None = Decimal("0.30")
    max_median_sale_days: int | None = Field(default=30, ge=1)
    require_velocity_data: bool = False
    min_product_confidence: Ratio = Decimal("0.75")
    min_authenticity_confidence: Ratio = Decimal("0.50")
    max_authenticity_risk: Ratio = Decimal("0.40")
    max_purchase_price: PositiveMoney = Decimal(300)
    max_capital_per_item: PositiveMoney = Decimal(320)
    max_inventory_exposure: PositiveMoney = Decimal(2000)
    max_units_per_product: int = Field(default=3, ge=1)
    exclude_kids_sizes: bool = True
    # What to do when the authenticity check could not look at enough (few photos, no seller
    # information): "review" asks you to check more; "reject" discards the listing.
    low_auth_confidence_action: Literal["review", "reject"] = "review"
    # Reject for counterfeit risk only when warning signs (not just the brand's prior) add at
    # least this much to the log-odds; below it, a high-risk listing goes to REVIEW.
    auth_reject_min_warning: Annotated[Decimal, Field(ge=0)] = Decimal("1.0")
    resale_basis: Literal["expected", "quick"] = "expected"
    high_priority: HighPriorityRules = Field(default_factory=HighPriorityRules)
    review: ReviewRules = Field(default_factory=ReviewRules)
    caps: TierCaps = Field(default_factory=TierCaps)
    realert: RealertRules = Field(default_factory=RealertRules)


# --------------------------------------------------------------------------- authenticity


LogOdds = Annotated[Decimal, Field(ge=-10, le=10)]


class ChecklistItem(StrictModel):
    """Something to look for in the photos. Shifts are in log-odds (see AuthenticityShifts)."""

    code: str = Field(pattern=r"^[a-z0-9_]{2,40}$")
    description: str
    observed_shift: LogOdds = Decimal("-0.5")  # seen and consistent: lowers risk
    concern_shift: LogOdds = Decimal("1.2")  # seen but questionable: raises risk
    recommended_check: str | None = None


class AuthenticityShifts(StrictModel):
    """How much each signal moves the odds that an item is counterfeit.

    ``logit(risk) = logit(brand base risk) + Σ shifts``. Positive shifts raise the risk,
    negative ones (good evidence) lower it. +0.7 roughly doubles the odds; -0.7 halves them.
    """

    price_anomaly_severe: LogOdds = Decimal("2.0")
    price_anomaly_moderate: LogOdds = Decimal("0.8")
    replica_language: LogOdds = Decimal("4.0")
    missing_tags_language: LogOdds = Decimal("0.6")
    seller_new_account: LogOdds = Decimal("0.4")
    seller_few_reviews: LogOdds = Decimal("0.3")
    seller_low_rating: LogOdds = Decimal("0.5")
    reused_photos_other_seller: LogOdds = Decimal("2.0")
    mislabel_derived: LogOdds = Decimal("0.8")
    contradictory_identification: LogOdds = Decimal("0.5")
    established_seller: LogOdds = Decimal("-0.5")
    trusted_seller: LogOdds = Decimal("-1.0")
    price_consistent_with_comps: LogOdds = Decimal("-0.2")


class AuthenticityConfidenceRules(StrictModel):
    base: Ratio = Decimal("0.20")
    per_photo: Ratio = Decimal("0.05")
    max_photo_bonus: Ratio = Decimal("0.20")
    per_observed_check: Ratio = Decimal("0.10")
    seller_info_bonus: Ratio = Decimal("0.05")
    comps_bonus: Ratio = Decimal("0.05")
    maximum: Ratio = Decimal("0.90")
    no_photos_cap: Ratio = Decimal("0.35")


class AuthenticityConfig(StrictModel):
    low_risk_below: Ratio = Decimal("0.25")
    high_risk_from: Ratio = Decimal("0.50")
    shifts: AuthenticityShifts = Field(default_factory=AuthenticityShifts)
    # Price anomaly vs the median of comparable sales. Flipping means buying below market, so
    # only extreme under-pricing counts as a warning sign.
    severe_price_ratio_to_median: Annotated[Decimal, Field(gt=0, le=1)] = Decimal("0.35")
    moderate_price_ratio_to_median: Annotated[Decimal, Field(gt=0, le=1)] = Decimal("0.50")
    new_account_days: int = Field(default=30, ge=0)
    few_reviews_below: int = Field(default=3, ge=0)
    low_rating_below: Annotated[Decimal, Field(ge=0, le=5)] = Decimal("4.5")
    established_min_reviews: int = Field(default=50, ge=1)
    established_min_rating: Annotated[Decimal, Field(ge=0, le=5)] = Decimal("4.8")
    duplicate_phash_max_distance: int = Field(default=4, ge=0, le=16)
    missing_tag_phrases: list[str] = Field(default_factory=list)
    confidence: AuthenticityConfidenceRules = Field(default_factory=AuthenticityConfidenceRules)
    brand_checklists: dict[str, list[ChecklistItem]] = Field(default_factory=dict)
    generic_recommended_checks: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _levels(self) -> AuthenticityConfig:
        if self.low_risk_below >= self.high_risk_from:
            raise ValueError("low_risk_below must be below high_risk_from")
        if self.severe_price_ratio_to_median >= self.moderate_price_ratio_to_median:
            raise ValueError("severe price ratio must be below the moderate one")
        return self


# --------------------------------------------------------------------------- identification


class AIIdentificationRules(StrictModel):
    enabled: bool = True
    # Ask the AI when the rules result is below this confidence or has contradictions.
    invoke_below_confidence: Ratio = Decimal("0.75")
    # Also send photos for the authenticity checklist whenever a listing has photos.
    analyse_photos: bool = True
    max_photos: int = Field(default=6, ge=1, le=20)
    max_confidence: Ratio = Decimal("0.80")
    agree_boost: Ratio = Decimal("0.5")
    disagree_factor: Ratio = Decimal("0.6")


class MislabelRules(StrictModel):
    enabled: bool = True
    min_price: PositiveMoney = Decimal(5)
    max_price: PositiveMoney = Decimal(150)
    require_keyword: bool = True
    keywords: list[str] = Field(default_factory=list)
    min_ai_confidence: Ratio = Decimal("0.5")
    max_confidence: Ratio = Decimal("0.60")


class MatchingRules(StrictModel):
    min_score: Ratio = Decimal("0.70")
    min_margin: Ratio = Decimal("0.08")
    fuzzy_min_similarity: Ratio = Decimal("0.70")
    # Applied when the listing's category was unknown and is inferred from the product.
    inferred_category_factor: Ratio = Decimal("0.90")


class IdentificationConfig(StrictModel):
    brand_field_confidence: Ratio = Decimal("0.95")
    brand_title_confidence: Ratio = Decimal("0.90")
    brand_description_confidence: Ratio = Decimal("0.60")
    brand_fuzzy_min_similarity: Ratio = Decimal("0.50")
    brand_fuzzy_factor: Ratio = Decimal("0.80")
    category_field_confidence: Ratio = Decimal("0.90")
    category_title_confidence: Ratio = Decimal("0.85")
    contradiction_factor: Ratio = Decimal("0.60")
    replica_factor: Ratio = Decimal("0.20")
    generic_brand_values: list[str] = Field(default_factory=list)
    replica_phrases: list[str] = Field(default_factory=list)
    ai: AIIdentificationRules = Field(default_factory=AIIdentificationRules)
    mislabel: MislabelRules = Field(default_factory=MislabelRules)
    matching: MatchingRules = Field(default_factory=MatchingRules)


# --------------------------------------------------------------------------- price guide


class PriceGuideEntry(StrictModel):
    """An operator-supplied reference resale price range (not sales data).

    Used only when no comparable-sales level has enough data. Evaluations priced this way are
    labelled and capped (``deal_rules.caps.price_guide``).
    """

    brand: str
    category: str
    product: str | None = None
    condition: Condition = Condition.VERY_GOOD
    low: PositiveMoney
    typical: PositiveMoney
    high: PositiveMoney
    currency: str = "GBP"
    note: str | None = None

    @model_validator(mode="after")
    def _ordered(self) -> PriceGuideEntry:
        if not (0 < self.low <= self.typical <= self.high):
            raise ValueError("price guide needs 0 < low <= typical <= high")
        return self


class PriceGuideConfig(StrictModel):
    entries: list[PriceGuideEntry] = Field(default_factory=list)


CONFIG_MODELS: dict[ConfigKind, type[StrictModel]] = {
    ConfigKind.DEAL_RULES: DealRulesConfig,
    ConfigKind.FEES: FeesConfig,
    ConfigKind.CONDITIONS: ConditionsConfig,
    ConfigKind.SIZES: SizesConfig,
    ConfigKind.MARKET: MarketConfig,
    ConfigKind.AUTHENTICITY: AuthenticityConfig,
    ConfigKind.IDENTIFICATION: IdentificationConfig,
    ConfigKind.PRICE_GUIDE: PriceGuideConfig,
}


def validate_config(kind: ConfigKind, payload: dict[str, Any]) -> StrictModel:
    """Validate a raw payload for ``kind``; raises ``pydantic.ValidationError``."""
    return CONFIG_MODELS[kind].model_validate(payload)


def dump_config(model: StrictModel) -> dict[str, Any]:
    """JSON-safe dict (Decimals as strings, so they round-trip exactly)."""
    return model.model_dump(mode="json")
