"""Performance benchmark at the planned scale (~500k listings, ~100k sales).

Creates (or resets) a separate database, applies the migrations, seeds reference data and a
synthetic market, then measures:

* the comparable-sales query (target: p95 < 50 ms),
* the sale-velocity lookups,
* full evaluation throughput (rules only, no AI).

    uv run python scripts/perf_benchmark.py                       # full scale
    uv run python scripts/perf_benchmark.py --listings 50000 --sales 20000

Never point it at your real database: it drops and recreates the schema.
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

from sqlalchemy import create_engine, insert, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

from app.core.time import utcnow  # noqa: E402
from app.models import Brand, Category, Listing, MarketSale, Product  # noqa: E402

DEFAULT_URL = "postgresql+psycopg://resale:resale@127.0.0.1:5432/resale_perf"
COMPS_P95_TARGET_MS = 50.0
SIZES = ["XS", "S", "M", "L", "XL", "XXL"]
CONDITIONS = ["new_with_tags", "new_without_tags", "very_good", "good", "satisfactory"]
COLOURS = ["black", "navy", "grey", "white", "olive", "blue"]


def ensure_database(url: str) -> None:
    target = make_url(url)
    admin = create_engine(target.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        exists = conn.scalar(
            text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": target.database}
        )
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{target.database}"'))
    admin.dispose()


def reset_schema(url: str) -> None:
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(ROOT / "migrations"))
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
    with Session(engine) as session:
        from app.services.seed import seed_reference_data

        seed_reference_data(session)
        session.commit()
    engine.dispose()


def timed(label: str, action: Callable[[], object]) -> float:
    started = time.perf_counter()
    action()
    elapsed = time.perf_counter() - started
    print(f"  {label}: {elapsed:.1f} s")
    return elapsed


def seed_market(session: Session, *, listings: int, sales: int, rng: random.Random) -> None:
    brands = list(session.scalars(select(Brand)))
    categories = list(session.scalars(select(Category)))
    products: dict[tuple[int, int], list[int]] = {}
    for product in session.scalars(select(Product)):
        products.setdefault((product.brand_id, product.category_id), []).append(product.id)
    pairs = [(b, c) for b in brands for c in categories if (b.id, c.id) in products]
    now = utcnow()

    def sale_rows(start: int, end: int) -> list[dict[str, object]]:
        rows = []
        for i in range(start, end):
            brand, category = rng.choice(pairs)
            sold_at = now - timedelta(days=rng.uniform(0, 730))
            rows.append(
                {
                    "source": rng.choice(["csv_import", "manual_entry", "own_sale"]),
                    "source_ref": f"bench:{i}",
                    "brand_id": brand.id,
                    "category_id": category.id,
                    "product_id": rng.choice(products[(brand.id, category.id)]),
                    "size_normalised": rng.choice(SIZES),
                    "colour": rng.choice(COLOURS),
                    "condition": rng.choice(CONDITIONS),
                    "sale_price": Decimal(rng.randint(1500, 60000)) / 100,
                    "currency": "GBP",
                    "price_type": "final_sale_price",
                    "sold_at": sold_at,
                    "listed_at": sold_at - timedelta(days=rng.uniform(0.5, 60)),
                }
            )
        return rows

    def listing_rows(start: int, end: int) -> list[dict[str, object]]:
        rows = []
        for i in range(start, end):
            brand, category = rng.choice(pairs)
            seen = now - timedelta(days=rng.uniform(0, 365))
            rows.append(
                {
                    "marketplace": "vinted",
                    "external_id": f"bench{i}",
                    "source": "api",
                    "title": f"{brand.name} {category.name.lower()} {rng.choice(COLOURS)} "
                    f"{rng.choice(SIZES)}",
                    "raw_brand": brand.name,
                    "raw_category": category.name,
                    "raw_size": rng.choice(SIZES),
                    "brand_id": brand.id,
                    "category_id": category.id,
                    "price": Decimal(rng.randint(1000, 40000)) / 100,
                    "currency": "GBP",
                    "first_seen_at": seen,
                    "last_seen_at": seen,
                    "status": rng.choice(["active"] * 3 + ["sold", "removed"]),
                    "content_hash": f"{i:064x}"[-64:],
                    "raw_payload": {},
                }
            )
        return rows

    batch = 5_000

    def insert_all(model: type, total: int, rows: Callable[[int, int], list[dict[str, object]]]):
        for start in range(0, total, batch):
            session.execute(insert(model), rows(start, min(start + batch, total)))
        session.commit()

    timed(f"{sales:,} sales", lambda: insert_all(MarketSale, sales, sale_rows))
    timed(f"{listings:,} listings", lambda: insert_all(Listing, listings, listing_rows))
    session.execute(text("ANALYZE"))
    session.commit()


def percentiles(samples_ms: list[float]) -> str:
    ordered = sorted(samples_ms)

    def pct(p: float) -> float:
        return ordered[min(len(ordered) - 1, int(p * len(ordered)))]

    return (
        f"p50 {statistics.median(ordered):.1f} ms · p95 {pct(0.95):.1f} ms · "
        f"p99 {pct(0.99):.1f} ms · max {ordered[-1]:.1f} ms"
    )


def measure(session: Session, *, queries: int, evaluations: int, rng: random.Random) -> bool:
    from app.services.config_service import ConfigService
    from app.services.market_data import COMP_COLUMNS, load_comps
    from app.services.pipeline import EvaluationContext, evaluate_listing
    from app.services.velocity import velocity_for

    bundle = ConfigService(session).bundle()
    pairs = [
        (row.brand_id, row.category_id)
        for row in session.execute(select(MarketSale.brand_id, MarketSale.category_id).distinct())
    ]
    now = utcnow()
    since = now - timedelta(days=bundle.market.window_days)

    query_ms, comps_ms, sizes = [], [], []
    for _ in range(queries):
        brand_id, category_id = rng.choice(pairs)
        query = select(*COMP_COLUMNS).where(
            MarketSale.brand_id == brand_id,
            MarketSale.category_id == category_id,
            MarketSale.excluded.is_(False),
            MarketSale.sold_at >= since,
            MarketSale.sold_at <= now,
        )
        started = time.perf_counter()
        session.execute(query).all()
        query_ms.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        comps = load_comps(
            session, brand_id=brand_id, category_id=category_id, since=since, until=now
        )
        comps_ms.append((time.perf_counter() - started) * 1000)
        sizes.append(len(comps))
    print(
        f"  comps query, rows fetched ({statistics.mean(sizes):.0f} each): {percentiles(query_ms)}"
    )
    print(f"  comps load incl. building the comp objects: {percentiles(comps_ms)}")

    velocity_ms = []
    for _ in range(max(queries // 5, 10)):
        brand_id, category_id = rng.choice(pairs)
        started = time.perf_counter()
        velocity_for(
            session, brand_id=brand_id, category_id=category_id, product_id=None,
            product_is_generic=True, as_of=now, rules=bundle.market.velocity,
            window_days=bundle.market.window_days,
        )  # fmt: skip
        velocity_ms.append((time.perf_counter() - started) * 1000)
    print(f"  velocity lookup (3 scopes): {percentiles(velocity_ms)}")

    ids = list(
        session.scalars(select(Listing.id).where(Listing.status == "active").limit(evaluations * 5))
    )
    sample = rng.sample(ids, min(evaluations, len(ids)))
    ctx = EvaluationContext(bundle=bundle, ai=None, media_dir=ROOT / "media", now=now)
    started = time.perf_counter()
    for listing_id in sample:
        listing = session.get(Listing, listing_id)
        assert listing is not None
        evaluate_listing(session, listing, ctx, trigger="backfill")
    session.rollback()
    elapsed = time.perf_counter() - started
    print(
        f"  full evaluations: {len(sample)} in {elapsed:.1f} s = "
        f"{len(sample) / elapsed:.1f} per second ({elapsed / len(sample) * 1000:.0f} ms each)"
    )

    p95 = sorted(query_ms)[int(0.95 * (len(query_ms) - 1))]
    ok = p95 < COMPS_P95_TARGET_MS
    verdict = "OK" if ok else "FAIL"
    print(f"\ncomps p95 {p95:.1f} ms vs target {COMPS_P95_TARGET_MS:.0f} ms: {verdict}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--database-url", default=DEFAULT_URL)
    parser.add_argument("--listings", type=int, default=500_000)
    parser.add_argument("--sales", type=int, default=100_000)
    parser.add_argument("--queries", type=int, default=500)
    parser.add_argument("--evaluations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--keep", action="store_true", help="reuse an already seeded database")
    args = parser.parse_args()
    if make_url(args.database_url).database in {"resale", "postgres"}:
        parser.error("refusing to reset what looks like a real database")

    rng = random.Random(args.seed)  # noqa: S311 - synthetic benchmark data
    print(f"Benchmark database: {make_url(args.database_url).render_as_string(hide_password=True)}")
    engine = create_engine(args.database_url)
    if not args.keep:
        ensure_database(args.database_url)
        print("Preparing schema and seed data")
        timed("migrations + seed", lambda: reset_schema(args.database_url))
        with Session(engine) as session:
            seed_market(session, listings=args.listings, sales=args.sales, rng=rng)
    print("Measuring")
    from app.core.runtime import freeze_startup_objects

    freeze_startup_objects()  # as the API, worker and bot do at start-up
    with Session(engine) as session:
        ok = measure(session, queries=args.queries, evaluations=args.evaluations, rng=rng)
    engine.dispose()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
