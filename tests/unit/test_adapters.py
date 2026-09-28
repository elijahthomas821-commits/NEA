"""Adapter contract suite and resilience wrapper."""

from __future__ import annotations

import random
from decimal import Decimal

import pytest

from app.collectors.base import (
    AccessDeniedError,
    AdapterHealth,
    AdapterPage,
    ListingQuery,
    NotSupportedError,
    PayloadInvalidError,
    RateLimitedError,
    RawListing,
    TransientError,
)
from app.collectors.fixture.adapter import FixtureAdapter
from app.collectors.manual.adapter import ManualAdapter
from app.collectors.registry import get_adapter, registered_marketplaces
from app.collectors.resilience import (
    AdapterDisabledError,
    CircuitBreaker,
    CircuitOpenError,
    ResilientAdapter,
    RetryPolicy,
    TokenBucket,
)
from app.core.errors import NotFoundError
from tests.factories import raw_listing


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds


def _fixture() -> FixtureAdapter:
    return FixtureAdapter(
        [
            raw_listing(external_id="1", title="Stone Island hoodie", price=Decimal("40")),
            raw_listing(external_id="2", title="Moncler Maya jacket", price=Decimal("300")),
        ]
    )


ADAPTERS = [
    pytest.param(lambda: ManualAdapter("vinted"), id="manual-vinted"),
    pytest.param(lambda: get_adapter("ebay"), id="registry-ebay"),
    pytest.param(_fixture, id="fixture"),
]


@pytest.mark.parametrize("factory", ADAPTERS)
class TestAdapterContract:
    """Every adapter must satisfy these, whatever its source."""

    def test_declares_capabilities_and_terms(self, factory):
        adapter = factory()
        caps = adapter.capabilities
        assert adapter.marketplace
        assert caps.terms_reference.strip()

    def test_health_check(self, factory):
        assert isinstance(factory().health_check(), AdapterHealth)

    def test_search_matches_capabilities(self, factory):
        adapter = factory()
        if adapter.capabilities.supports_search:
            page = adapter.search_listings(ListingQuery())
            assert isinstance(page, AdapterPage)
            assert all(isinstance(item, RawListing) for item in page.items)
        else:
            with pytest.raises(NotSupportedError):
                adapter.search_listings(ListingQuery())

    def test_lookup_matches_capabilities(self, factory):
        adapter = factory()
        if adapter.capabilities.supports_item_lookup:
            assert adapter.get_listing("does-not-exist") is None
        else:
            with pytest.raises(NotSupportedError):
                adapter.get_listing("x")

    def test_manual_sources_are_not_automated(self, factory):
        adapter = factory()
        if isinstance(adapter, ManualAdapter):
            assert adapter.capabilities.automated is False


def test_registry():
    assert {"vinted", "ebay", "depop", "other"} <= set(registered_marketplaces())
    with pytest.raises(NotFoundError):
        get_adapter("nope")


def test_fixture_search_filters():
    adapter = _fixture()
    page = adapter.search_listings(ListingQuery(keywords=["moncler"]))
    assert [i.external_id for i in page.items] == ["2"]
    page = adapter.search_listings(ListingQuery(max_price=Decimal("100")))
    assert [i.external_id for i in page.items] == ["1"]


class TestResilience:
    def _wrapped(self, failures, **kwargs):
        clock = FakeClock()
        inner = _fixture()
        inner.failures = failures
        wrapped = ResilientAdapter(
            inner,
            retry=kwargs.pop("retry", RetryPolicy(max_attempts=4, base_delay=1, jitter=0)),
            breaker=kwargs.pop("breaker", CircuitBreaker(failure_threshold=10, clock=clock)),
            sleep=clock.sleep,
            rng=random.Random(1),
            **kwargs,
        )
        return wrapped, inner, clock

    def test_transient_errors_retried_with_exponential_backoff(self):
        wrapped, inner, clock = self._wrapped([TransientError("503"), TransientError("timeout")])
        assert wrapped.get_listing("1") is not None
        assert inner.calls == 3
        assert clock.slept == [1.0, 2.0]

    def test_gives_up_after_max_attempts(self):
        wrapped, inner, _ = self._wrapped([TransientError("x")] * 10)
        with pytest.raises(TransientError):
            wrapped.get_listing("1")
        assert inner.calls == 4

    def test_rate_limit_retry_after_is_honoured_exactly(self):
        wrapped, _, clock = self._wrapped([RateLimitedError(retry_after=17.5)])
        assert wrapped.get_listing("1") is not None
        assert clock.slept == [17.5]

    def test_access_denied_disables_and_is_never_retried(self):
        disabled = []
        wrapped, inner, clock = self._wrapped(
            [AccessDeniedError("403 challenge")],
            on_disabled=lambda mp, reason: disabled.append((mp, reason)),
        )
        with pytest.raises(AccessDeniedError):
            wrapped.get_listing("1")
        assert inner.calls == 1
        assert clock.slept == []
        assert disabled == [("vinted", "403 challenge")]
        with pytest.raises(AdapterDisabledError):
            wrapped.get_listing("1")
        assert inner.calls == 1  # no further calls once disabled
        assert wrapped.health_check().ok is False

    def test_payload_invalid_propagates_without_retry(self):
        wrapped, inner, _ = self._wrapped([PayloadInvalidError("bad json", raw="{")])
        with pytest.raises(PayloadInvalidError) as err:
            wrapped.get_listing("1")
        assert err.value.raw == "{"
        assert inner.calls == 1

    def test_circuit_breaker_opens_and_recovers(self):
        clock = FakeClock()
        breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60, clock=clock)
        wrapped, _inner, _ = self._wrapped(
            [TransientError("a"), TransientError("b")],
            breaker=breaker,
            retry=RetryPolicy(max_attempts=5, base_delay=1, jitter=0),
        )
        with pytest.raises(TransientError):
            wrapped.get_listing("1")
        assert breaker.is_open
        with pytest.raises(CircuitOpenError):
            wrapped.get_listing("1")
        clock.t += 61
        assert not breaker.is_open  # half-open
        assert wrapped.get_listing("1") is not None
        assert breaker.failures == 0

    def test_token_bucket_throttles(self):
        clock = FakeClock()
        bucket = TokenBucket(60, clock=clock, sleep=clock.sleep)
        for _ in range(60):
            assert bucket.acquire() == 0.0
        waited = bucket.acquire()
        assert waited == pytest.approx(1.0)

    def test_retry_delay_is_capped(self):
        policy = RetryPolicy(base_delay=10, max_delay=30, jitter=0)
        assert policy.delay(5, random.Random(0)) == 30

    def test_invalid_bucket_rate(self):
        with pytest.raises(ValueError, match="positive"):
            TokenBucket(0)
