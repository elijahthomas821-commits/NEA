"""Rate limiting, retries with backoff, circuit breaking and access-denied handling.

:class:`ResilientAdapter` wraps any :class:`MarketplaceAdapter`:

* honours the adapter's own request budget (token bucket);
* retries :class:`TransientError` with exponential backoff and jitter;
* honours :class:`RateLimitedError.retry_after` exactly;
* opens a circuit breaker after repeated failures;
* on :class:`AccessDeniedError` disables the adapter permanently (until an operator re-enables
  it) and raises — it never retries, rotates identities or tries to get around a block.

Clock and sleep are injectable so the behaviour is fully testable without waiting.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TypeVar

from app.collectors.base import (
    AccessDeniedError,
    AdapterCapabilities,
    AdapterError,
    AdapterHealth,
    AdapterPage,
    ListingQuery,
    MarketplaceAdapter,
    RateLimitedError,
    RawListing,
    TransientError,
)
from app.core.logging import get_logger

log = get_logger(__name__)
T = TypeVar("T")


class AdapterDisabledError(AdapterError):
    """The adapter was disabled after an access-denied response."""


class CircuitOpenError(AdapterError):
    """Too many recent failures; calls are refused until the cool-down passes."""


class TokenBucket:
    def __init__(
        self,
        rate_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        self.capacity = float(rate_per_minute)
        self.tokens = float(rate_per_minute)
        self.refill_per_second = rate_per_minute / 60.0
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Take one token, sleeping if necessary. Returns seconds waited."""
        with self._lock:
            now = self._clock()
            self.tokens = min(
                self.capacity, self.tokens + (now - self._last) * self.refill_per_second
            )
            self._last = now
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            wait = (1 - self.tokens) / self.refill_per_second
        self._sleep(wait)
        with self._lock:
            self._last = self._clock()
            self.tokens = 0.0
        return wait


@dataclass
class RetryPolicy:
    max_attempts: int = 4
    base_delay: float = 1.0
    max_delay: float = 60.0
    jitter: float = 0.25  # +/- fraction of the delay

    def delay(self, attempt: int, rng: random.Random) -> float:
        raw = min(self.max_delay, self.base_delay * (2.0 ** (attempt - 1)))
        spread = raw * self.jitter
        return max(0.0, raw + rng.uniform(-spread, spread))


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 300.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock
        self.failures = 0
        self.opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        # After the cool-down the breaker is half-open: one trial call is allowed.
        return self._clock() - self.opened_at < self.cooldown_seconds

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = self._clock()


class ResilientAdapter:
    """Applies rate limiting, retries and circuit breaking to an adapter."""

    def __init__(
        self,
        inner: MarketplaceAdapter,
        *,
        retry: RetryPolicy | None = None,
        breaker: CircuitBreaker | None = None,
        bucket: TokenBucket | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
        on_disabled: Callable[[str, str], None] | None = None,
    ) -> None:
        self.inner = inner
        self.marketplace = inner.marketplace
        self.capabilities: AdapterCapabilities = inner.capabilities
        self.retry = retry or RetryPolicy()
        self.breaker = breaker or CircuitBreaker()
        limit = inner.capabilities.max_requests_per_minute
        self.bucket = bucket or (TokenBucket(limit, sleep=sleep) if limit else None)
        self._sleep = sleep
        self._rng = rng or random.Random()  # noqa: S311 - jitter, not security
        self._on_disabled = on_disabled
        self.disabled_reason: str | None = None

    def _call(self, operation: str, fn: Callable[[], T]) -> T:
        if self.disabled_reason is not None:
            raise AdapterDisabledError(
                f"{self.marketplace} adapter disabled: {self.disabled_reason}"
            )
        if self.breaker.is_open:
            raise CircuitOpenError(f"{self.marketplace} circuit open after repeated failures")

        attempt = 0
        while True:
            attempt += 1
            if self.bucket is not None:
                self.bucket.acquire()
            try:
                result = fn()
            except AccessDeniedError as exc:
                self.disabled_reason = str(exc) or "access denied"
                log.error(
                    "adapter_access_denied", marketplace=self.marketplace, operation=operation
                )
                if self._on_disabled is not None:
                    self._on_disabled(self.marketplace, self.disabled_reason)
                raise
            except RateLimitedError as exc:
                self.breaker.record_failure()
                if attempt >= self.retry.max_attempts:
                    raise
                log.warning(
                    "adapter_rate_limited",
                    marketplace=self.marketplace,
                    retry_after=exc.retry_after,
                )
                self._sleep(exc.retry_after)
                continue
            except TransientError:
                self.breaker.record_failure()
                if attempt >= self.retry.max_attempts or self.breaker.is_open:
                    raise
                delay = self.retry.delay(attempt, self._rng)
                log.warning(
                    "adapter_transient_error",
                    marketplace=self.marketplace,
                    attempt=attempt,
                    delay=round(delay, 2),
                )
                self._sleep(delay)
                continue
            self.breaker.record_success()
            return result

    def search_listings(
        self, query: ListingQuery, since: datetime | None = None
    ) -> AdapterPage[RawListing]:
        return self._call("search", lambda: self.inner.search_listings(query, since))

    def get_listing(self, external_id: str) -> RawListing | None:
        return self._call("get", lambda: self.inner.get_listing(external_id))

    def health_check(self) -> AdapterHealth:
        if self.disabled_reason is not None:
            return AdapterHealth(ok=False, detail=f"disabled: {self.disabled_reason}")
        if self.breaker.is_open:
            return AdapterHealth(ok=False, detail="circuit open")
        return self.inner.health_check()
