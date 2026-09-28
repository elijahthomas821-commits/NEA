"""The manual adapter: marks a marketplace whose listings arrive only by operator submission."""

from __future__ import annotations

from datetime import datetime

from app.collectors.base import (
    AdapterCapabilities,
    AdapterHealth,
    AdapterPage,
    ListingQuery,
    NotSupportedError,
    RawListing,
)

MANUAL_CAPABILITIES = AdapterCapabilities(
    supports_search=False,
    supports_item_lookup=False,
    supports_status_refresh=False,
    automated=False,
    max_requests_per_minute=None,
    terms_reference="Operator-submitted listings only; no automated access to the marketplace.",
)


class ManualAdapter:
    """Listings come from you (Telegram, API, CSV). Search and lookup are not available."""

    def __init__(self, marketplace: str) -> None:
        self.marketplace = marketplace
        self.capabilities = MANUAL_CAPABILITIES

    def search_listings(
        self, query: ListingQuery, since: datetime | None = None
    ) -> AdapterPage[RawListing]:
        raise NotSupportedError(f"{self.marketplace}: listings are submitted manually")

    def get_listing(self, external_id: str) -> RawListing | None:
        raise NotSupportedError(f"{self.marketplace}: listings are submitted manually")

    def health_check(self) -> AdapterHealth:
        return AdapterHealth(ok=True, detail="manual intake")
