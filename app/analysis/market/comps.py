"""Comparable-sales selection and statistics (the pricing evidence).

For a target listing the engine:

1. drops ineligible sales (outside the window, sold after the evaluation time, asking-price-only
   when configured so, currency not convertible) — each with a recorded reason;
2. walks the fallback hierarchy L1 → L6 (most to least specific) and, at each level,
   normalises every comp to the target (currency → condition → size, and a haircut for
   last-asking-price observations), weights it by recency × source trust × match confidence,
   and flags outliers (flagged, never deleted);
3. uses the first level whose sample size and effective sample size (Kish) clear the
   configured minimums, and reports weighted percentiles, dispersion and a confidence score.

If no level has enough data there is no estimate — the listing cannot qualify
(``INSUFFICIENT_MARKET_DATA``). Brand-less, category-only data is never used for price.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.market.stats import (
    ONE,
    ZERO,
    effective_sample_size,
    outlier_fences,
    recency_weight,
    weighted_geometric_mean,
    weighted_mean,
    weighted_percentile,
)
from app.config.schemas import ConditionsConfig, MarketConfig, SizesConfig
from app.core.enums import CompLevel, Condition, PriceType, SaleSource
from app.core.time import age_days

STANDARD_PERCENTILES = {
    "p10": Decimal("0.10"),
    "p25": Decimal("0.25"),
    "p50": Decimal("0.50"),
    "p75": Decimal("0.75"),
    "p90": Decimal("0.90"),
}
PRODUCT_LEVELS = {CompLevel.L1, CompLevel.L2, CompLevel.L3, CompLevel.L4}


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class CompSale:
    """One comparable sale as the engine sees it (a plain dataclass: thousands are built per
    evaluation, from database rows that the schema already constrains)."""

    id: int
    product_id: int | None
    brand_id: int
    category_id: int
    size: str | None = None
    colour: str | None = None
    condition: Condition | None = None
    price: Decimal
    currency: str
    price_type: PriceType = PriceType.FINAL_SALE_PRICE
    source: SaleSource
    marketplace: str | None = None
    sold_at: datetime
    listed_at: datetime | None = None
    trust_weight: Decimal = ONE
    match_confidence: Decimal = ONE


class CompTarget(Frozen):
    product_id: int | None
    product_is_generic: bool
    brand_id: int
    category_id: int
    category_slug: str | None = None
    size: str | None = None
    colour: str | None = None
    condition: Condition | None = None
    currency: str
    match_confidence: Decimal = ONE
    as_of: datetime


class FxTable(Frozen):
    """Manually recorded FX rates: ``rates[(base, quote)] = [(as_of, rate), ...]``."""

    rates: dict[str, list[tuple[date, Decimal]]] = Field(default_factory=dict)

    @staticmethod
    def key(base: str, quote: str) -> str:
        return f"{base}/{quote}"

    def rate(self, base: str, quote: str, on: date, max_age_days: int) -> Decimal | None:
        if base == quote:
            return ONE
        for key, invert in ((self.key(base, quote), False), (self.key(quote, base), True)):
            history = [(d, r) for d, r in self.rates.get(key, []) if d <= on]
            if history:
                as_of, rate = max(history, key=lambda item: item[0])
                if (on - as_of).days <= max_age_days:
                    return ONE / rate if invert else rate
        return None


class AdjustedComp(Frozen):
    sale_id: int
    level: CompLevel
    original_price: Decimal
    original_currency: str
    adjusted_price: Decimal
    weight: Decimal
    recency: Decimal
    trust: Decimal
    match: Decimal
    condition_ratio: Decimal
    size_ratio: Decimal
    haircut: Decimal
    fx_rate: Decimal
    sold_at: datetime
    listed_at: datetime | None
    is_outlier: bool = False


class ExcludedComp(Frozen):
    sale_id: int
    reason: str


class LevelAttempt(Frozen):
    level: CompLevel
    sample_size: int
    effective_sample_size: Decimal
    outliers: int
    accepted: bool
    reason: str


class MarketResult(Frozen):
    currency: str
    level: CompLevel | None = None
    sample_size: int = 0
    effective_sample_size: Decimal = ZERO
    percentiles: dict[str, Decimal] = Field(default_factory=dict)
    weighted_mean: Decimal | None = None
    dispersion: Decimal | None = None
    recency_factor: Decimal = ZERO
    confidence: Decimal = ZERO
    comps: list[AdjustedComp] = Field(default_factory=list)
    outliers: list[AdjustedComp] = Field(default_factory=list)
    excluded: list[ExcludedComp] = Field(default_factory=list)
    attempts: list[LevelAttempt] = Field(default_factory=list)

    @property
    def has_estimate(self) -> bool:
        return self.level is not None

    def percentile(self, q: Decimal) -> Decimal:
        pairs = [(c.adjusted_price, c.weight) for c in self.comps]
        return weighted_percentile(pairs, q)


def _condition_multiplier(condition: Condition | None, cfg: ConditionsConfig) -> Decimal:
    return cfg.multipliers[condition or cfg.assume_when_unknown]


def _size_multiplier(size: str | None, category_slug: str | None, cfg: SizesConfig) -> Decimal:
    if size is None:
        return ONE
    table = cfg.multipliers.get(category_slug or "", cfg.multipliers["default"])
    return table.get(size, cfg.multipliers["default"].get(size, ONE))


def _matches(level: CompLevel, target: CompTarget, comp: CompSale) -> bool:
    if level in PRODUCT_LEVELS and (
        target.product_id is None or comp.product_id != target.product_id
    ):
        return False
    if level in (CompLevel.L5, CompLevel.L6) and (
        comp.brand_id != target.brand_id or comp.category_id != target.category_id
    ):
        return False
    needs_size = level in (CompLevel.L1, CompLevel.L2)
    needs_condition = level in (CompLevel.L1, CompLevel.L2, CompLevel.L3, CompLevel.L5)
    if needs_size and (target.size is None or comp.size != target.size):
        return False
    if needs_condition and (target.condition is None or comp.condition != target.condition):
        return False
    return not (level == CompLevel.L1 and (target.colour is None or comp.colour != target.colour))


def select_eligible(
    target: CompTarget, sales: Sequence[CompSale], cfg: MarketConfig, fx: FxTable
) -> tuple[list[tuple[CompSale, Decimal]], list[ExcludedComp]]:
    """Sales usable as price evidence, each with its FX rate into the target currency."""
    eligible: list[tuple[CompSale, Decimal]] = []
    excluded: list[ExcludedComp] = []
    for sale in sales:
        age = age_days(sale.sold_at, target.as_of)
        if sale.sold_at > target.as_of:
            excluded.append(ExcludedComp(sale_id=sale.id, reason="sold after the evaluation time"))
            continue
        if age > cfg.window_days:
            excluded.append(ExcludedComp(sale_id=sale.id, reason="outside the comparison window"))
            continue
        if (
            sale.price_type == PriceType.LAST_ASKING_PRICE
            and not cfg.last_asking_price.use_for_price
        ):
            excluded.append(ExcludedComp(sale_id=sale.id, reason="asking price only (speed data)"))
            continue
        rate = fx.rate(sale.currency, target.currency, sale.sold_at.date(), cfg.fx_max_age_days)
        if rate is None:
            excluded.append(
                ExcludedComp(
                    sale_id=sale.id,
                    reason=f"no {sale.currency}->{target.currency} rate for the sale date",
                )
            )
            continue
        eligible.append((sale, rate))
    return eligible, excluded


def adjust(
    sale: CompSale,
    fx_rate: Decimal,
    level: CompLevel,
    target: CompTarget,
    *,
    market: MarketConfig,
    conditions: ConditionsConfig,
    sizes: SizesConfig,
) -> AdjustedComp:
    haircut = ONE
    trust = market.source_trust.get(sale.source, Decimal("0.5"))
    trust *= market.marketplace_trust.get(
        sale.marketplace or "default", market.marketplace_trust["default"]
    )
    trust *= sale.trust_weight
    if sale.price_type == PriceType.LAST_ASKING_PRICE:
        haircut = market.last_asking_price.haircut
        trust *= market.last_asking_price.trust_multiplier
    if sale.condition is None:
        trust *= market.unknown_condition_weight

    condition_ratio = _condition_multiplier(target.condition, conditions) / _condition_multiplier(
        sale.condition, conditions
    )
    size_ratio = ONE
    if target.size is not None and sale.size is not None:
        size_ratio = _size_multiplier(target.size, target.category_slug, sizes) / _size_multiplier(
            sale.size, target.category_slug, sizes
        )
    recency = recency_weight(
        Decimal(str(age_days(sale.sold_at, target.as_of))), market.half_life_days
    )
    adjusted = sale.price * fx_rate * haircut * condition_ratio * size_ratio
    # Built from values computed just above (trusted), so validation is skipped.
    return AdjustedComp.model_construct(
        sale_id=sale.id,
        level=level,
        original_price=sale.price,
        original_currency=sale.currency,
        adjusted_price=adjusted,
        weight=recency * trust * sale.match_confidence,
        recency=recency,
        trust=trust,
        match=sale.match_confidence,
        condition_ratio=condition_ratio,
        size_ratio=size_ratio,
        haircut=haircut,
        fx_rate=fx_rate,
        sold_at=sale.sold_at,
        listed_at=sale.listed_at,
    )


def estimate_market(
    target: CompTarget,
    sales: Sequence[CompSale],
    *,
    market: MarketConfig,
    conditions: ConditionsConfig,
    sizes: SizesConfig,
    fx: FxTable | None = None,
) -> MarketResult:
    fx = fx or FxTable()
    eligible, excluded = select_eligible(target, sales, market, fx)
    attempts: list[LevelAttempt] = []

    for level in market.levels:
        if level in PRODUCT_LEVELS and (target.product_id is None or target.product_is_generic):
            continue  # a generic match has no model-level comps
        comps = [
            adjust(sale, rate, level, target, market=market, conditions=conditions, sizes=sizes)
            for sale, rate in eligible
            if _matches(level, target, sale)
        ]
        comps = [c for c in comps if c.weight > 0]
        fences = outlier_fences(
            [c.adjusted_price for c in comps],
            min_n=market.outliers.min_n,
            iqr_min_n=market.outliers.iqr_min_n,
            iqr_k=market.outliers.iqr_k,
            mad_k=market.outliers.mad_k,
        )
        inliers, outliers = comps, []
        if fences is not None:
            low, high = fences
            inliers = [c for c in comps if low <= c.adjusted_price <= high]
            outliers = [
                c.model_copy(update={"is_outlier": True})
                for c in comps
                if not low <= c.adjusted_price <= high
            ]
        n = len(inliers)
        # Rounded before comparing: equal weights must give exactly n, not n - 1e-27.
        n_eff = effective_sample_size([c.weight for c in inliers]).quantize(Decimal("0.000001"))
        enough = n >= market.min_sample_size and n_eff >= market.min_effective_n
        attempts.append(
            LevelAttempt(
                level=level,
                sample_size=n,
                effective_sample_size=n_eff.quantize(Decimal("0.01")),
                outliers=len(outliers),
                accepted=enough,
                reason="enough data"
                if enough
                else (
                    f"{n} sales (min {market.min_sample_size}), "
                    f"effective n {n_eff.quantize(Decimal('0.1'))} (min {market.min_effective_n})"
                ),
            )
        )
        if not enough:
            continue

        pairs = [(c.adjusted_price, c.weight) for c in inliers]
        percentiles = {
            name: weighted_percentile(pairs, q) for name, q in STANDARD_PERCENTILES.items()
        }
        dispersion = (
            (percentiles["p75"] - percentiles["p25"]) / percentiles["p50"]
            if percentiles["p50"] > 0
            else None
        )
        total_weight = sum((c.weight for c in inliers), ZERO)
        recency_factor = sum((c.weight * c.recency for c in inliers), ZERO) / total_weight
        confidence = market_confidence(
            n_eff=n_eff,
            level=level,
            dispersion=dispersion,
            recency_factor=recency_factor,
            match_confidence=target.match_confidence,
            market=market,
        )
        return MarketResult(
            currency=target.currency,
            level=level,
            sample_size=n,
            effective_sample_size=n_eff,
            percentiles=percentiles,
            weighted_mean=weighted_mean(pairs),
            dispersion=dispersion,
            recency_factor=recency_factor,
            confidence=confidence,
            comps=inliers,
            outliers=outliers,
            excluded=excluded,
            attempts=attempts,
        )
    return MarketResult(currency=target.currency, excluded=excluded, attempts=attempts)


def market_confidence(
    *,
    n_eff: Decimal,
    level: CompLevel,
    dispersion: Decimal | None,
    recency_factor: Decimal,
    match_confidence: Decimal,
    market: MarketConfig,
) -> Decimal:
    """Weighted geometric mean of five factors, each in (0, 1]:

    * sample: ``n_eff / (n_eff + n_scale)``
    * level: configured factor for the fallback level
    * dispersion: ``1 / (1 + (IQR / median) / dispersion_scale)``
    * recency: weight-averaged recency of the comps
    * match: confidence that the listing is the product the comps describe
    """
    rules = market.confidence
    f_n = n_eff / (n_eff + rules.n_scale)
    f_level = rules.level_factors.get(level, Decimal("0.5"))
    f_disp = ONE / (ONE + (dispersion or ZERO) / rules.dispersion_scale)
    weights = rules.factor_weights
    return weighted_geometric_mean(
        [
            (f_n, weights.get("n", ONE)),
            (f_level, weights.get("level", ONE)),
            (f_disp, weights.get("dispersion", ONE)),
            (recency_factor, weights.get("recency", ONE)),
            (match_confidence, weights.get("match", ONE)),
        ]
    ).quantize(Decimal("0.001"))
