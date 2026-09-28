"""How fast similar items sell.

Median days to sale is estimated with the Kaplan–Meier estimator so that items that are listed
but have *not yet sold* (your own unsold stock) count as censored observations — "at least N
days so far". Using completed sales alone would overstate the speed (survivorship bias).

Scopes are tried from most to least specific (the pricing level's comps, then brand + category,
then category only); category-only data is used for speed, never for price.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.analysis.market.comps import CompSale
from app.config.schemas import VelocityRules
from app.core.time import age_days

ZERO = Decimal(0)
ONE = Decimal(1)
HALF = Decimal("0.5")
LiquidityLabel = Literal["high", "medium", "low"]


class VelocityScope(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    sales: list[CompSale]
    censored_days: list[Decimal] = []  # days listed so far for unsold items
    active_observed: int = 0


class VelocityResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    scope: str | None = None
    median_days_to_sale: Decimal | None = None
    events: int = 0
    censored: int = 0
    sales_last_30d: int = 0
    sales_last_90d: int = 0
    active_observed: int = 0
    sell_through: Decimal | None = None
    liquidity_score: Decimal | None = None
    liquidity_label: LiquidityLabel | None = None

    @property
    def known(self) -> bool:
        return self.median_days_to_sale is not None


def kaplan_meier_median(observations: Sequence[tuple[Decimal, bool]]) -> Decimal | None:
    """Median survival time from (duration, sold) pairs; None if the median is not reached.

    At each distinct sale time t: S(t) = S(t⁻) · (1 − sold_at_t / at_risk_t), where items
    censored at t are still counted as at risk at t. The median is the first t with S(t) ≤ ½.
    """
    if not observations:
        return None
    times = sorted({duration for duration, sold in observations if sold})
    survival = ONE
    for t in times:
        at_risk = sum(1 for duration, _ in observations if duration >= t)
        sold_now = sum(1 for duration, sold in observations if sold and duration == t)
        if at_risk == 0:
            continue
        survival *= ONE - Decimal(sold_now) / Decimal(at_risk)
        if survival <= HALF:
            return t
    return None


def _days_to_sale(sale: CompSale) -> Decimal | None:
    if sale.listed_at is None or sale.listed_at > sale.sold_at:
        return None
    return Decimal(str(round(age_days(sale.listed_at, sale.sold_at), 1)))


def estimate_velocity(
    scopes: Sequence[VelocityScope], *, as_of: datetime, rules: VelocityRules
) -> VelocityResult:
    for scope in scopes:
        events = [d for d in (_days_to_sale(s) for s in scope.sales) if d is not None]
        if len(events) < rules.min_events:
            continue
        observations = [(d, True) for d in events] + [(d, False) for d in scope.censored_days]
        median = kaplan_meier_median(observations)
        recent = [s for s in scope.sales if s.sold_at <= as_of]
        last_30 = sum(1 for s in recent if s.sold_at >= as_of - timedelta(days=30))
        last_90 = sum(1 for s in recent if s.sold_at >= as_of - timedelta(days=90))
        sell_through = (
            Decimal(last_30) / Decimal(last_30 + scope.active_observed)
            if last_30 + scope.active_observed > 0
            else None
        )
        liquidity = liquidity_score(median, last_90, rules)
        return VelocityResult(
            scope=scope.name,
            median_days_to_sale=median,
            events=len(events),
            censored=len(scope.censored_days),
            sales_last_30d=last_30,
            sales_last_90d=last_90,
            active_observed=scope.active_observed,
            sell_through=sell_through,
            liquidity_score=liquidity,
            liquidity_label=liquidity_label(liquidity, rules),
        )
    return VelocityResult()


def liquidity_score(
    median_days: Decimal | None, sales_90d: int, rules: VelocityRules
) -> Decimal | None:
    """0–1: speed (vs twice the target days) blended with recent volume."""
    if median_days is None:
        return None
    speed = min(ONE, max(ZERO, ONE - median_days / (2 * Decimal(rules.target_days))))
    volume = Decimal(sales_90d) / (Decimal(sales_90d) + rules.volume_scale)
    score = rules.speed_weight * speed + (ONE - rules.speed_weight) * volume
    return score.quantize(Decimal("0.001"))


def liquidity_label(score: Decimal | None, rules: VelocityRules) -> LiquidityLabel | None:
    if score is None:
        return None
    if score >= rules.high_liquidity_from:
        return "high"
    if score >= rules.medium_liquidity_from:
        return "medium"
    return "low"
