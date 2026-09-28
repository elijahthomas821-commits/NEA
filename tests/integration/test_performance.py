"""The comparable-sales query stays fast and indexed as market data grows.

A lighter version of ``scripts/perf_benchmark.py`` (which seeds the plan's full ~500k listings /
~100k sales): 30 000 sales across every brand x category, spread over two years.
"""

from __future__ import annotations

import json
import random
import time
from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import insert, select, text

from app.core.time import utcnow
from app.models import Brand, Category, MarketSale, Product
from app.services.market_data import COMP_COLUMNS, load_comps
from app.services.velocity import velocity_for

pytestmark = [pytest.mark.integration, pytest.mark.slow]

SALES = 30_000
P95_BUDGET_MS = 50.0


def seed_sales(session, count: int, *, seed: int = 7) -> list[tuple[int, int]]:
    rng = random.Random(seed)
    brands = list(session.scalars(select(Brand.id)))
    categories = list(session.scalars(select(Category.id)))
    products = {(p.brand_id, p.category_id): p.id for p in session.scalars(select(Product))}
    pairs = [(b, c) for b in brands for c in categories if (b, c) in products]
    now = utcnow()
    rows = []
    for i in range(count):
        brand_id, category_id = rng.choice(pairs)
        sold_at = now - timedelta(days=rng.uniform(0, 730))
        rows.append(
            {
                "source": "csv_import",
                "source_ref": f"perf:{i}",
                "brand_id": brand_id,
                "category_id": category_id,
                "product_id": products[(brand_id, category_id)],
                "size_normalised": rng.choice(["S", "M", "L", "XL"]),
                "condition": rng.choice(["new_with_tags", "very_good", "good"]),
                "sale_price": Decimal(rng.randint(2000, 30000)) / 100,
                "currency": "GBP",
                "price_type": "final_sale_price",
                "sold_at": sold_at,
                "listed_at": sold_at - timedelta(days=rng.uniform(1, 40)),
            }
        )
    for start in range(0, len(rows), 5_000):
        session.execute(insert(MarketSale), rows[start : start + 5_000])
    session.execute(text("ANALYZE market_sales"))
    return pairs


def p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[int(0.95 * (len(ordered) - 1))]


def test_comps_query_is_fast_and_indexed(db_session):
    pairs = seed_sales(db_session, SALES)
    now = utcnow()
    since = now - timedelta(days=365)
    timings = []
    for brand_id, category_id in pairs * 8:
        started = time.perf_counter()
        comps = load_comps(
            db_session, brand_id=brand_id, category_id=category_id, since=since, until=now
        )
        timings.append((time.perf_counter() - started) * 1000)
        assert all(since <= c.sold_at <= now for c in comps)
    assert p95(timings) < P95_BUDGET_MS, f"comps p95 {p95(timings):.1f} ms"

    brand_id, category_id = pairs[0]
    query = select(*COMP_COLUMNS).where(
        MarketSale.brand_id == brand_id,
        MarketSale.category_id == category_id,
        MarketSale.excluded.is_(False),
        MarketSale.sold_at >= since,
        MarketSale.sold_at <= now,
    )
    compiled = query.compile(compile_kwargs={"literal_binds": True})
    plan = db_session.execute(text(f"EXPLAIN (FORMAT JSON) {compiled}")).scalar_one()
    assert "ix_market_sales_brand_category_sold" in json.dumps(plan)


def test_velocity_is_windowed(db_session):
    from app.config.loader import load_default_config
    from app.core.enums import ConfigKind

    pairs = seed_sales(db_session, 5_000, seed=11)
    rules = load_default_config(ConfigKind.MARKET).velocity  # type: ignore[attr-defined]
    brand_id, category_id = pairs[0]
    started = time.perf_counter()
    result = velocity_for(
        db_session, brand_id=brand_id, category_id=category_id, product_id=None,
        product_is_generic=True, as_of=utcnow(), rules=rules, window_days=365,
    )  # fmt: skip
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert result.median_days_to_sale is not None
    assert elapsed_ms < 1000
