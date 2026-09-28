"""A deterministic in-memory adapter.

Serves a fixed list of :class:`RawListing` objects and can be told to fail in specific ways, so
the adapter contract and the resilience wrapper can be tested without any network.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from app.analysis.normalisation.text import normalise_text
from app.collectors.base import (
    AdapterCapabilities,
    AdapterError,
    AdapterHealth,
    AdapterPage,
    ListingQuery,
    RawListing,
)

FIXTURE_CAPABILITIES = AdapterCapabilities(
    supports_search=True,
    supports_item_lookup=True,
    supports_status_refresh=True,
    automated=True,
    max_requests_per_minute=None,
    terms_reference="Test fixture; no external access.",
)


class FixtureAdapter:
    def __init__(
        self,
        listings: Iterable[RawListing],
        *,
        marketplace: str = "vinted",
        failures: list[AdapterError] | None = None,
    ) -> None:
        self.marketplace = marketplace
        self.capabilities = FIXTURE_CAPABILITIES
        self._listings = list(listings)
        # Errors raised by successive calls before normal behaviour resumes.
        self.failures = list(failures or [])
        self.calls = 0

    def _maybe_fail(self) -> None:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)

    def search_listings(
        self, query: ListingQuery, since: datetime | None = None
    ) -> AdapterPage[RawListing]:
        self._maybe_fail()
        keywords = [normalise_text(k) for k in query.keywords]
        results = []
        for listing in self._listings:
            text = normalise_text(f"{listing.title} {listing.raw_brand or ''}")
            if keywords and not all(k in text for k in keywords):
                continue
            if query.max_price is not None and (
                listing.price is None or listing.price > query.max_price
            ):
                continue
            if since is not None and listing.listed_at is not None and listing.listed_at < since:
                continue
            results.append(listing)
        return AdapterPage[RawListing](items=results[: query.limit])

    def get_listing(self, external_id: str) -> RawListing | None:
        self._maybe_fail()
        return next((item for item in self._listings if item.external_id == external_id), None)

    def health_check(self) -> AdapterHealth:
        return AdapterHealth(ok=True, detail=f"{len(self._listings)} fixture listings")
