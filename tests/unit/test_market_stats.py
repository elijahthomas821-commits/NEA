from decimal import Decimal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from app.analysis.market.stats import (
    effective_sample_size,
    median,
    outlier_fences,
    percentile,
    recency_weight,
    weighted_geometric_mean,
    weighted_mean,
    weighted_percentile,
)

D = Decimal
prices = st.decimals(min_value=1, max_value=5000, places=2, allow_nan=False, allow_infinity=False)
weights = st.decimals(
    min_value="0.01", max_value=10, places=3, allow_nan=False, allow_infinity=False
)
quantiles = st.decimals(min_value=0, max_value=1, places=3)
pairs_strategy = st.lists(st.tuples(prices, weights), min_size=1, max_size=40)


def hazen_reference(values: list[Decimal], q: Decimal) -> Decimal:
    """Independent textbook implementation of the Hazen percentile, for cross-checking."""
    xs = sorted(values)
    n = len(xs)
    h = q * n - D("0.5")  # zero-based fractional index
    if h <= 0:
        return xs[0]
    if h >= n - 1:
        return xs[-1]
    lower = int(h)
    return xs[lower] + (xs[lower + 1] - xs[lower]) * (h - lower)


class TestWeightedPercentile:
    def test_simple_cases(self):
        assert weighted_percentile([(D(10), D(1))], D("0.5")) == 10
        assert median([D(1), D(2), D(3)]) == 2
        assert median([D(1), D(2), D(3), D(4)]) == D("2.5")
        # A heavy weight pulls the median towards its value.
        assert weighted_percentile([(D(10), D(1)), (D(20), D(9))], D("0.5")) > 15

    def test_rejects_bad_input(self):
        with pytest.raises(ValueError, match="positive"):
            weighted_percentile([], D("0.5"))
        with pytest.raises(ValueError, match="within"):
            weighted_percentile([(D(1), D(1))], D("1.5"))

    @given(pairs_strategy, quantiles, quantiles)
    def test_monotonic_in_q(self, pairs, a, b):
        lo, hi = min(a, b), max(a, b)
        assert weighted_percentile(pairs, lo) <= weighted_percentile(pairs, hi)

    @given(pairs_strategy, quantiles)
    def test_bounded_by_min_and_max(self, pairs, q):
        values = [v for v, _ in pairs]
        result = weighted_percentile(pairs, q)
        assert min(values) <= result <= max(values)

    @given(st.lists(prices, min_size=1, max_size=40), quantiles)
    def test_equal_weights_match_hazen(self, values, q):
        assert abs(percentile(values, q) - hazen_reference(values, q)) < D("1e-20")

    @given(pairs_strategy, quantiles, st.decimals(min_value="0.1", max_value=10, places=2))
    def test_scale_invariance(self, pairs, q, k):
        scaled = [(v * k, w) for v, w in pairs]
        assert abs(weighted_percentile(scaled, q) - weighted_percentile(pairs, q) * k) < D("1e-15")

    @given(pairs_strategy, quantiles, st.decimals(min_value="0.1", max_value=10, places=2))
    def test_weight_scaling_invariance(self, pairs, q, k):
        rescaled = [(v, w * k) for v, w in pairs]
        assert abs(weighted_percentile(rescaled, q) - weighted_percentile(pairs, q)) < D("1e-15")

    @given(pairs_strategy)
    def test_percentile_ladder_is_ordered(self, pairs):
        ladder = [weighted_percentile(pairs, D(q)) for q in ("0.1", "0.25", "0.5", "0.75", "0.9")]
        assert ladder == sorted(ladder)


class TestOtherStats:
    @given(st.lists(weights, min_size=1, max_size=40))
    def test_effective_n_bounds(self, ws):
        n_eff = effective_sample_size(ws)
        assert D(1) - D("1e-20") <= n_eff <= D(len(ws)) + D("1e-20")

    def test_effective_n_equal_weights(self):
        assert effective_sample_size([D(2)] * 7) == 7
        assert effective_sample_size([]) == 0

    def test_effective_n_dominated_by_one_weight(self):
        assert effective_sample_size([D(100), D("0.01"), D("0.01")]) < D("1.001")

    def test_recency(self):
        assert recency_weight(D(0), D(90)) == 1
        assert recency_weight(D(90), D(90)) == D("0.5")
        assert recency_weight(D(180), D(90)) == D("0.25")

    @given(st.decimals(min_value=0, max_value=3650, places=1))
    def test_recency_bounded(self, age):
        assert D(0) < recency_weight(age, D(90)) <= 1

    def test_weighted_mean(self):
        assert weighted_mean([(D(10), D(1)), (D(20), D(3))]) == D("17.5")

    def test_geometric_mean(self):
        assert weighted_geometric_mean([(D(1), D(1)), (D(1), D(2))]) == 1
        assert weighted_geometric_mean([(D("0.25"), D(1)), (D(1), D(1))]).quantize(D("0.001")) == D(
            "0.500"
        )
        assert weighted_geometric_mean([(D(0), D(1)), (D(1), D(1))]) == 0
        assert weighted_geometric_mean([]) == 0

    @settings(max_examples=50)
    @given(
        st.lists(
            st.tuples(st.decimals(min_value="0.01", max_value=1, places=3), weights),
            min_size=1,
            max_size=6,
        )
    )
    def test_geometric_mean_between_min_and_max(self, factors):
        result = weighted_geometric_mean(factors)
        values = [f for f, _ in factors]
        assert min(values) - D("1e-20") <= result <= max(values) + D("1e-20")


class TestOutlierFences:
    def test_too_few_values(self):
        assert (
            outlier_fences([D(1), D(2), D(3)], min_n=4, iqr_min_n=8, iqr_k=D("1.5"), mad_k=D(3))
            is None
        )

    def test_mad_for_small_samples(self):
        values = [D(v) for v in (100, 105, 95, 102, 400)]
        low, high = outlier_fences(values, min_n=4, iqr_min_n=8, iqr_k=D("1.5"), mad_k=D(3))
        assert low < 95
        assert high < 400

    def test_iqr_for_larger_samples(self):
        values = [D(v) for v in (80, 85, 90, 95, 100, 105, 110, 115, 900)]
        low, high = outlier_fences(values, min_n=4, iqr_min_n=8, iqr_k=D("1.5"), mad_k=D(3))
        assert high < 900
        assert low <= 80

    def test_identical_values_have_no_outliers(self):
        assert (
            outlier_fences([D(50)] * 10, min_n=4, iqr_min_n=8, iqr_k=D("1.5"), mad_k=D(3)) is None
        )

    @given(st.lists(prices, min_size=4, max_size=30))
    def test_fences_contain_the_median(self, values):
        fences = outlier_fences(values, min_n=4, iqr_min_n=8, iqr_k=D("1.5"), mad_k=D(3))
        assume(fences is not None)
        low, high = fences
        assert low <= median(values) <= high
