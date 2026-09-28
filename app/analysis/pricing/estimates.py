"""Turning market evidence into resale price estimates.

* From comparable sales: quick / expected / optimistic are configured weighted percentiles
  (default P25 / median / P75) of the adjusted comps.
* From your price guide (only when no comps level qualifies): your low / typical / high
  range, adjusted to the listing's condition and size, with a fixed low confidence.

Estimates are expectations, not guarantees; every one carries its basis, sample size and
confidence so the deal rules can treat weak evidence accordingly.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.analysis.market.comps import MarketResult
from app.config.schemas import (
    ConditionsConfig,
    EstimatePercentiles,
    PriceGuideConfig,
    PriceGuideEntry,
    PriceGuideRules,
    SizesConfig,
)
from app.core.enums import CompLevel, Condition

HUNDRED = Decimal(100)


class PriceEstimate(BaseModel):
    model_config = ConfigDict(frozen=True)

    basis: Literal["comps", "price_guide"]
    currency: str
    quick: Decimal
    expected: Decimal
    optimistic: Decimal
    confidence: Decimal
    level: CompLevel
    sample_size: int = 0
    effective_sample_size: Decimal = Decimal(0)
    dispersion: Decimal | None = None
    p10: Decimal | None = None
    p25: Decimal | None = None
    p90: Decimal | None = None
    note: str | None = None


def estimate_from_market(
    result: MarketResult, percentiles: EstimatePercentiles
) -> PriceEstimate | None:
    if not result.has_estimate or result.level is None:
        return None
    return PriceEstimate(
        basis="comps",
        currency=result.currency,
        quick=result.percentile(percentiles.quick / HUNDRED),
        expected=result.percentile(percentiles.expected / HUNDRED),
        optimistic=result.percentile(percentiles.optimistic / HUNDRED),
        confidence=result.confidence,
        level=result.level,
        sample_size=result.sample_size,
        effective_sample_size=result.effective_sample_size,
        dispersion=result.dispersion,
        p10=result.percentiles.get("p10"),
        p25=result.percentiles.get("p25"),
        p90=result.percentiles.get("p90"),
    )


def _guide_entry(
    guide: PriceGuideConfig,
    *,
    brand_slug: str,
    category_slug: str,
    product_slug: str | None,
    currency: str,
) -> PriceGuideEntry | None:
    candidates = [
        e
        for e in guide.entries
        if e.brand == brand_slug and e.category == category_slug and e.currency == currency
    ]
    if product_slug is not None:
        specific = [e for e in candidates if e.product == product_slug]
        if specific:
            return specific[0]
    general = [e for e in candidates if e.product is None]
    return general[0] if general else None


def estimate_from_guide(
    guide: PriceGuideConfig,
    rules: PriceGuideRules,
    *,
    brand_slug: str | None,
    category_slug: str | None,
    product_slug: str | None,
    condition: Condition | None,
    size: str | None,
    currency: str,
    conditions: ConditionsConfig,
    sizes: SizesConfig,
) -> PriceEstimate | None:
    if not rules.enabled or brand_slug is None or category_slug is None:
        return None
    entry = _guide_entry(
        guide,
        brand_slug=brand_slug,
        category_slug=category_slug,
        product_slug=product_slug,
        currency=currency,
    )
    if entry is None:
        return None
    target_condition = condition or conditions.assume_when_unknown
    ratio = conditions.multipliers[target_condition] / conditions.multipliers[entry.condition]
    if size is not None:
        table = sizes.multipliers.get(category_slug, sizes.multipliers["default"])
        ratio *= table.get(size, Decimal(1))
    scope = f"{entry.brand}/{entry.category}" + (f"/{entry.product}" if entry.product else "")
    return PriceEstimate(
        basis="price_guide",
        currency=currency,
        quick=entry.low * ratio,
        expected=entry.typical * ratio,
        optimistic=entry.high * ratio,
        confidence=rules.confidence,
        level=CompLevel.GUIDE,
        note=f"from your price guide ({scope}); not sales data",
    )
