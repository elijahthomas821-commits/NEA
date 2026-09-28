"""Adapter lookup by marketplace code."""

from __future__ import annotations

from collections.abc import Callable

from app.collectors.base import MarketplaceAdapter
from app.core.errors import NotFoundError

_factories: dict[str, Callable[[], MarketplaceAdapter]] = {}


def register_adapter(marketplace: str, factory: Callable[[], MarketplaceAdapter]) -> None:
    _factories[marketplace] = factory


def get_adapter(marketplace: str) -> MarketplaceAdapter:
    factory = _factories.get(marketplace)
    if factory is None:
        raise NotFoundError(f"no adapter registered for marketplace {marketplace!r}")
    return factory()


def registered_marketplaces() -> list[str]:
    return sorted(_factories)


def _register_builtin() -> None:
    from app.collectors.manual.adapter import ManualAdapter

    register_adapter("vinted", lambda: ManualAdapter("vinted"))
    register_adapter("ebay", lambda: ManualAdapter("ebay"))
    register_adapter("depop", lambda: ManualAdapter("depop"))
    register_adapter("other", lambda: ManualAdapter("other"))


_register_builtin()
