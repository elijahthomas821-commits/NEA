from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.collectors.base import RawSale
from app.core.enums import CompLevel, Condition, PriceType, ProductLevel, SaleSource
from app.core.errors import ValidationFailedError
from app.models import MarketStatistic, Product
from app.services.audit import Actor
from app.services.catalogue import load_catalogue
from app.services.csv_import import import_sales_csv
from app.services.market_data import add_fx_rate, load_comps, record_sale, set_excluded
from app.services.market_stats import recompute_market_statistics
from app.services.pricing import price_target
from tests.factories import NOW

pytestmark = pytest.mark.integration
ACTOR = Actor.system("test")


def raw(**overrides) -> RawSale:
    data = {
        "source": SaleSource.MANUAL_ENTRY,
        "brand": "Stone Island",
        "category": "sweatshirts",
        "title": "Stone Island garment dyed crewneck navy",
        "size": "L",
        "condition": "Very good",
        "sale_price": Decimal("95.00"),
        "currency": "GBP",
        "marketplace": "vinted",
        "sold_at": NOW - timedelta(days=5),
    }
    data.update(overrides)
    return RawSale(**data)


@pytest.fixture
def recorder(db_session, config_bundle):
    catalogue = load_catalogue(db_session)

    def record(sale: RawSale):
        return record_sale(
            db_session,
            sale,
            catalogue=catalogue,
            identification=config_bundle.identification,
            sizes=config_bundle.sizes,
            actor=ACTOR,
        )

    return record


def product_by_slug(db_session, slug):
    return db_session.scalar(select(Product).where(Product.slug == slug))


class TestRecordSale:
    def test_resolves_and_normalises(self, db_session, recorder):
        row, created = recorder(raw())
        assert created
        crewneck = product_by_slug(db_session, "crewneck-sweatshirt")
        assert row.product_id == crewneck.id
        assert (row.size_normalised, row.condition, row.colour) == ("L", "very_good", "navy")
        assert row.source_ref.startswith("auto:")

    def test_same_comp_twice_is_not_duplicated(self, recorder):
        first, created1 = recorder(raw())
        second, created2 = recorder(raw())
        assert created1
        assert not created2
        assert first.id == second.id

    def test_explicit_source_ref_dedupes(self, recorder):
        _, a = recorder(raw(source_ref="ebay:123"))
        _, b = recorder(raw(source_ref="ebay:123", sale_price=Decimal("80")))
        assert a
        assert not b

    def test_brand_by_alias_and_category_by_keyword(self, recorder):
        row, _ = recorder(raw(brand="c.p. company", category="Hoodie", title="goggle hoodie"))
        assert row.category_id is not None
        assert row.product_id is not None

    def test_generic_product_when_model_unknown(self, db_session, recorder):
        row, _ = recorder(raw(title="Stone Island sweatshirt"))
        product = db_session.get(Product, row.product_id)
        assert product.level == ProductLevel.BRAND_CATEGORY_GENERIC.value

    def test_explicit_product(self, db_session, recorder):
        row, _ = recorder(raw(product="half-zip-sweatshirt", title=None))
        assert row.product_id == product_by_slug(db_session, "half-zip-sweatshirt").id

    def test_days_to_sale(self, recorder):
        row, _ = recorder(raw(listed_at=NOW - timedelta(days=20), sold_at=NOW - timedelta(days=5)))
        assert row.days_to_sale == 15

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"brand": "Nike"}, "unknown brand"),
            ({"category": "spacesuits"}, "unknown category"),
            ({"category": "cap", "title": "Stone Island cap"}, "not in scope"),
            ({"marketplace": "nope"}, "unknown marketplace"),
            ({"product": "does-not-exist"}, "unknown product"),
        ],
    )
    def test_validation(self, recorder, overrides, message):
        with pytest.raises(ValidationFailedError, match=message):
            recorder(raw(**overrides))


class TestPricingEndToEnd:
    def _price(self, db_session, bundle, **overrides):
        catalogue = load_catalogue(db_session)
        brand = catalogue.brand_by_slug("stone-island")
        category = catalogue.category_by_slug("sweatshirts")
        crewneck = product_by_slug(db_session, "crewneck-sweatshirt")
        args = {
            "brand_id": brand.id,
            "category_id": category.id,
            "product_id": crewneck.id,
            "size": "L",
            "colour": "navy",
            "condition": Condition.VERY_GOOD,
            "currency": "GBP",
            "match_confidence": Decimal("0.9"),
            "as_of": NOW,
        }
        args.update(overrides)
        return price_target(db_session, bundle, catalogue, **args)

    def test_no_data(self, db_session, config_bundle):
        outcome = self._price(db_session, config_bundle)
        assert outcome.estimate is None
        assert not outcome.market.has_estimate

    def test_estimate_from_recorded_comps(self, db_session, config_bundle, recorder):
        for price in ("90", "95", "100", "105", "110", "98"):
            recorder(raw(sale_price=Decimal(price), source_ref=f"t:{price}"))
        outcome = self._price(db_session, config_bundle)
        assert outcome.estimate is not None
        assert outcome.estimate.basis == "comps"
        assert outcome.market.level is CompLevel.L1
        assert Decimal(95) < outcome.estimate.expected < Decimal(105)

    def test_excluded_comps_are_ignored(self, db_session, config_bundle, recorder):
        rows = [recorder(raw(sale_price=Decimal(p), source_ref=f"x:{p}"))[0] for p in (90, 95, 100)]
        set_excluded(db_session, rows[0].id, excluded=True, reason="typo", actor=ACTOR)
        brand_id, category_id = rows[0].brand_id, rows[0].category_id
        assert len(load_comps(db_session, brand_id=brand_id, category_id=category_id)) == 2

    def test_price_guide_fallback(self, db_session, config_bundle):
        guide = config_bundle.price_guide.model_validate(
            {
                "entries": [
                    {
                        "brand": "stone-island",
                        "category": "sweatshirts",
                        "low": "60",
                        "typical": "80",
                        "high": "100",
                    }
                ]
            }
        )
        bundle = config_bundle.__class__(**{**config_bundle.__dict__, "price_guide": guide})
        outcome = self._price(db_session, bundle)
        assert outcome.used_price_guide
        assert outcome.estimate.expected == Decimal(80)

    def test_foreign_currency_comps_need_fx(self, db_session, config_bundle, recorder):
        for price in ("110", "115", "120", "118", "112"):
            recorder(raw(sale_price=Decimal(price), currency="EUR", source_ref=f"e:{price}"))
        assert self._price(db_session, config_bundle).estimate is None
        add_fx_rate(
            db_session, base="GBP", quote="EUR", rate=Decimal("1.18"),
            as_of=(NOW - timedelta(days=6)).date(), actor=ACTOR,
        )  # fmt: skip
        outcome = self._price(db_session, config_bundle)
        assert outcome.estimate is not None
        assert Decimal(90) < outcome.estimate.expected < Decimal(105)


class TestCsvSales:
    def test_import(self, db_session, recorder):
        good = "Stone Island,sweatshirts,crewneck navy,L,Very good,95,GBP,2026-08-20,"
        rows = [
            "brand,category,title,size,condition,sale_price,currency,sold_at,price_type",
            good + "final_sale_price",
            "Moncler,jackets,Maya black,3,Good,450,,2026-08-10,last_asking_price",
            "Nike,hoodies,tech fleece,M,Good,40,GBP,2026-08-10,",
            good + "final_sale_price",
            "Stone Island,sweatshirts,crewneck,L,Good,,GBP,2026-08-20,",
            "Stone Island,sweatshirts,crewneck,L,Good,90,GBP,2099-01-01,",
        ]
        content = "\n".join(rows) + "\n"
        run = import_sales_csv(
            db_session, content.encode(), source="comps.csv", base_currency="GBP", now=NOW,
            record=recorder,
        )  # fmt: skip
        assert (run.rows_created, run.rows_skipped, run.rows_failed) == (2, 1, 3)
        errors = {e["line"]: " ".join(e["errors"]) for e in run.report["errors"]}
        assert "unknown brand" in errors[4]
        assert "sale_price" in errors[6]
        assert "future" in errors[7]

    def test_missing_columns(self, db_session, recorder):
        run = import_sales_csv(
            db_session, b"brand,price\nx,1\n", source="c", base_currency="GBP", now=NOW,
            record=recorder,
        )  # fmt: skip
        assert run.status == "failed"


class TestFxRates:
    def test_upsert(self, db_session):
        add_fx_rate(
            db_session,
            base="gbp",
            quote="eur",
            rate=Decimal("1.17"),
            as_of=date(2026, 9, 1),
            actor=ACTOR,
        )
        row = add_fx_rate(
            db_session,
            base="GBP",
            quote="EUR",
            rate=Decimal("1.18"),
            as_of=date(2026, 9, 1),
            actor=ACTOR,
        )
        assert row.rate == Decimal("1.18")

    def test_validation(self, db_session):
        with pytest.raises(ValidationFailedError):
            add_fx_rate(
                db_session,
                base="GBP",
                quote="GBP",
                rate=Decimal(1),
                as_of=date(2026, 9, 1),
                actor=ACTOR,
            )


def test_market_statistics_snapshot(db_session, config_bundle, recorder):
    for i, price in enumerate(("90", "100", "110")):
        recorder(
            raw(
                sale_price=Decimal(price),
                source_ref=f"s:{i}",
                listed_at=NOW - timedelta(days=12),
                sold_at=NOW - timedelta(days=2),
            )
        )
    recorder(
        raw(
            sale_price=Decimal("300"),
            title="Stone Island sweatshirt",
            source_ref="g:1",
            price_type=PriceType.LAST_ASKING_PRICE,
        )
    )
    created = recompute_market_statistics(
        db_session, now=NOW, cfg=config_bundle.market, currency="GBP"
    )
    assert created == 2  # one product row (crewneck) + one brand x category row
    rows = {r.scope_level: r for r in db_session.scalars(select(MarketStatistic))}
    product_row = rows["L4"]
    assert product_row.sample_size == 3
    assert product_row.median == Decimal("100.00")
    assert product_row.median_days_to_sale == Decimal("10.0")
    assert product_row.sales_last_30d == 3
    assert rows["L6"].sample_size == 4
    # Recompute replaces rather than accumulates.
    assert (
        recompute_market_statistics(db_session, now=NOW, cfg=config_bundle.market, currency="GBP")
        == 2
    )
    assert len(db_session.scalars(select(MarketStatistic)).all()) == 2
