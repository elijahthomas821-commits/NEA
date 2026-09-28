from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.core.enums import InventoryStatus
from app.models import InventoryItem, Product, Purchase
from app.services.catalogue import load_catalogue
from app.services.velocity import velocity_for
from tests.factories import NOW
from tests.integration.test_market_data import raw

pytestmark = pytest.mark.integration


def _scope_ids(db_session):
    catalogue = load_catalogue(db_session)
    brand = catalogue.brand_by_slug("stone-island")
    category = catalogue.category_by_slug("sweatshirts")
    product = db_session.scalar(select(Product).where(Product.slug == "crewneck-sweatshirt"))
    return brand.id, category.id, product.id


def test_velocity_falls_back_to_brand_category(db_session, config_bundle, recorder):
    brand_id, category_id, product_id = _scope_ids(db_session)
    for i, days in enumerate((4, 8, 12)):
        recorder(
            raw(
                title="Stone Island sweatshirt",
                source_ref=f"v{i}",
                listed_at=NOW - timedelta(days=days + 1),
                sold_at=NOW - timedelta(days=1),
            )
        )
    result = velocity_for(
        db_session, brand_id=brand_id, category_id=category_id, product_id=product_id,
        product_is_generic=False, as_of=NOW, rules=config_bundle.market.velocity,
    )  # fmt: skip
    assert result.scope == "brand+category"
    assert result.median_days_to_sale == Decimal(8)


def test_unsold_stock_is_censored(db_session, config_bundle, recorder):
    brand_id, category_id, product_id = _scope_ids(db_session)
    for i, days in enumerate((3, 5, 7)):
        recorder(
            raw(
                source_ref=f"c{i}",
                listed_at=NOW - timedelta(days=days + 1),
                sold_at=NOW - timedelta(days=1),
            )
        )
    purchase = Purchase(
        marketplace="vinted", purchased_at=NOW - timedelta(days=40), currency="GBP",
        purchase_price=Decimal(40), total_acquisition_cost=Decimal(40),
    )  # fmt: skip
    db_session.add(purchase)
    db_session.flush()
    for days in (20, 25, 30):
        db_session.add(
            InventoryItem(
                purchase_id=purchase.id, product_id=product_id, brand_id=brand_id,
                category_id=category_id, title="unsold", currency="GBP",
                allocated_acquisition_cost=Decimal(40), status=InventoryStatus.LISTED.value,
                listed_at=NOW - timedelta(days=days),
            )
        )  # fmt: skip
    db_session.flush()
    result = velocity_for(
        db_session, brand_id=brand_id, category_id=category_id, product_id=product_id,
        product_is_generic=False, as_of=NOW, rules=config_bundle.market.velocity,
    )  # fmt: skip
    assert result.scope == "product"
    assert result.censored == 3
    assert result.median_days_to_sale == Decimal(7)


def test_no_data(db_session, config_bundle):
    brand_id, category_id, product_id = _scope_ids(db_session)
    result = velocity_for(
        db_session, brand_id=brand_id, category_id=category_id, product_id=product_id,
        product_is_generic=False, as_of=NOW, rules=config_bundle.market.velocity,
    )  # fmt: skip
    assert not result.known
