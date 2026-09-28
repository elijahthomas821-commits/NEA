"""Weighted statistics in exact Decimal arithmetic.

Weighted percentile definition (documented in docs/financial-calculations.md): sort values;
give value *i* the plotting position ``p_i = (W_{<i} + w_i / 2) / W`` (the midpoint of its
weight interval); interpolate linearly between positions and clamp outside them. With equal
weights this reduces to the Hazen definition ``p_i = (i + 0.5) / n``.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

ZERO = Decimal(0)
ONE = Decimal(1)
HALF = Decimal("0.5")
MAD_TO_SIGMA = Decimal("1.4826")


def recency_weight(age_days: Decimal, half_life_days: Decimal) -> Decimal:
    """``0.5 ** (age / half_life)``: a sale one half-life old counts half as much."""
    if age_days <= 0:
        return ONE
    return HALF ** (age_days / half_life_days)


def effective_sample_size(weights: Sequence[Decimal]) -> Decimal:
    """Kish's effective sample size ``(Σw)² / Σw²`` (equals n when all weights are equal)."""
    total = sum(weights, ZERO)
    squares = sum((w * w for w in weights), ZERO)
    if squares == 0:
        return ZERO
    return (total * total) / squares


def weighted_percentile(pairs: Sequence[tuple[Decimal, Decimal]], q: Decimal) -> Decimal:
    """Weighted percentile of ``(value, weight)`` pairs; ``q`` in [0, 1]."""
    items = sorted((v, w) for v, w in pairs if w > 0)
    if not items:
        raise ValueError("no positive weights")
    if not ZERO <= q <= ONE:
        raise ValueError("q must be within [0, 1]")
    total = sum((w for _, w in items), ZERO)
    positions: list[Decimal] = []
    running = ZERO
    for _, weight in items:
        positions.append((running + weight / 2) / total)
        running += weight
    if q <= positions[0]:
        return items[0][0]
    if q >= positions[-1]:
        return items[-1][0]
    for i in range(len(items) - 1):
        lo, hi = positions[i], positions[i + 1]
        if lo <= q <= hi:
            if hi == lo:
                return items[i][0]
            fraction = (q - lo) / (hi - lo)
            return items[i][0] + (items[i + 1][0] - items[i][0]) * fraction
    return items[-1][0]  # pragma: no cover - unreachable given the clamps above


def percentile(values: Sequence[Decimal], q: Decimal) -> Decimal:
    """Unweighted (Hazen) percentile."""
    return weighted_percentile([(v, ONE) for v in values], q)


def median(values: Sequence[Decimal]) -> Decimal:
    return percentile(values, HALF)


def weighted_mean(pairs: Sequence[tuple[Decimal, Decimal]]) -> Decimal:
    total = sum((w for _, w in pairs), ZERO)
    if total == 0:
        raise ValueError("no positive weights")
    return sum((v * w for v, w in pairs), ZERO) / total


def outlier_fences(
    values: Sequence[Decimal],
    *,
    min_n: int,
    iqr_min_n: int,
    iqr_k: Decimal,
    mad_k: Decimal,
) -> tuple[Decimal, Decimal] | None:
    """(low, high) fences, or None when there is too little data to call anything an outlier.

    With at least ``iqr_min_n`` values: Tukey fences ``Q1 - k·IQR`` / ``Q3 + k·IQR``.
    With fewer: median ± ``mad_k`` × 1.4826 × MAD (robust for small samples).
    """
    n = len(values)
    if n < min_n:
        return None
    if n >= iqr_min_n:
        q1 = percentile(values, Decimal("0.25"))
        q3 = percentile(values, Decimal("0.75"))
        spread = q3 - q1
        if spread == 0:
            return None
        return q1 - iqr_k * spread, q3 + iqr_k * spread
    centre = median(values)
    mad = median([abs(v - centre) for v in values])
    if mad == 0:
        return None
    width = mad_k * MAD_TO_SIGMA * mad
    return centre - width, centre + width


def weighted_geometric_mean(factors: Sequence[tuple[Decimal, Decimal]]) -> Decimal:
    """``exp(Σ a·ln f / Σ a)`` for (factor, weight) pairs; any zero factor gives zero."""
    total_weight = sum((a for _, a in factors if a > 0), ZERO)
    if total_weight == 0:
        return ZERO
    log_sum = ZERO
    for factor, weight in factors:
        if weight <= 0:
            continue
        if factor <= 0:
            return ZERO
        log_sum += weight * min(factor, ONE).ln()
    return (log_sum / total_weight).exp()
