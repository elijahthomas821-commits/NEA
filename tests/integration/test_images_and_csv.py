from __future__ import annotations

from io import BytesIO

import pytest
from PIL import Image
from sqlalchemy import select

from app.core.errors import ValidationFailedError
from app.models import IngestionRun, Listing
from app.services.csv_import import import_listings_csv
from app.services.images import add_listing_image, find_reused_photos, read_image
from app.services.ingestion import ingest_listing
from tests.factories import NOW, image_bytes, raw_listing, raw_seller

pytestmark = pytest.mark.integration


@pytest.fixture
def listing(db_session):
    return ingest_listing(db_session, raw_listing(), source="api", now=NOW).listing


def _add(db_session, listing, data, tmp_path, **kwargs):
    return add_listing_image(
        db_session,
        listing,
        data,
        media_dir=tmp_path,
        max_bytes=kwargs.pop("max_bytes", 5_000_000),
        max_images=kwargs.pop("max_images", 5),
        **kwargs,
    )


class TestImages:
    def test_store_and_read_back(self, db_session, listing, tmp_path):
        data = image_bytes(seed=1)
        stored = _add(db_session, listing, data, tmp_path)
        assert stored.created
        image = stored.image
        assert image.position == 0
        assert image.content_type == "image/jpeg"
        assert len(image.phash) == 16
        assert read_image(tmp_path, image.storage_key) == data

    def test_same_photo_twice_is_deduplicated(self, db_session, listing, tmp_path):
        data = image_bytes(seed=2)
        first = _add(db_session, listing, data, tmp_path)
        second = _add(db_session, listing, data, tmp_path)
        assert not second.created
        assert second.image.id == first.image.id

    def test_positions_increment(self, db_session, listing, tmp_path):
        positions = [
            _add(db_session, listing, image_bytes(seed=s), tmp_path).image.position
            for s in range(3)
        ]
        assert positions == [0, 1, 2]

    def test_png_and_webp_accepted(self, db_session, listing, tmp_path):
        assert _add(db_session, listing, image_bytes(seed=4, fmt="PNG"), tmp_path).created
        assert _add(db_session, listing, image_bytes(seed=5, fmt="WEBP"), tmp_path).created

    @pytest.mark.parametrize(
        ("data", "message"),
        [
            (b"", "empty"),
            (b"not an image at all", "not a valid image"),
            (b"GIF89a" + b"\x00" * 100, "not a valid image"),
        ],
    )
    def test_rejects_invalid(self, db_session, listing, tmp_path, data, message):
        with pytest.raises(ValidationFailedError, match=message):
            _add(db_session, listing, data, tmp_path)

    def test_rejects_unsupported_format(self, db_session, listing, tmp_path):
        buffer = BytesIO()
        Image.new("RGB", (20, 20)).save(buffer, format="GIF")
        with pytest.raises(ValidationFailedError, match="unsupported image format"):
            _add(db_session, listing, buffer.getvalue(), tmp_path)

    def test_rejects_oversize(self, db_session, listing, tmp_path):
        with pytest.raises(ValidationFailedError, match="larger than"):
            _add(db_session, listing, image_bytes(seed=1), tmp_path, max_bytes=100)

    def test_limit_per_listing(self, db_session, listing, tmp_path):
        for seed in range(2):
            _add(db_session, listing, image_bytes(seed=seed), tmp_path, max_images=2)
        with pytest.raises(ValidationFailedError, match="at most 2"):
            _add(db_session, listing, image_bytes(seed=9), tmp_path, max_images=2)

    def test_path_traversal_blocked(self, tmp_path):
        with pytest.raises(ValidationFailedError):
            read_image(tmp_path, "../../etc/passwd")

    def test_reused_photo_on_other_sellers_listing(self, db_session, tmp_path):
        photo = image_bytes(seed=7, size=(640, 480))
        first = ingest_listing(
            db_session, raw_listing(seller=raw_seller()), source="api", now=NOW
        ).listing
        _add(db_session, first, photo, tmp_path)
        # A re-compressed copy of the same photo on another seller's listing.
        buffer = BytesIO()
        Image.open(BytesIO(photo)).resize((400, 300)).save(buffer, format="JPEG", quality=55)
        second = ingest_listing(
            db_session, raw_listing(seller=raw_seller()), source="api", now=NOW
        ).listing
        _add(db_session, second, buffer.getvalue(), tmp_path)
        db_session.refresh(second)
        matches = find_reused_photos(db_session, second, max_distance=4)
        assert [m["other_listing_id"] for m in matches] == [first.id]

    def test_same_seller_relisting_is_not_reuse(self, db_session, tmp_path):
        seller = raw_seller()
        photo = image_bytes(seed=8)
        a = ingest_listing(db_session, raw_listing(seller=seller), source="api", now=NOW).listing
        b = ingest_listing(db_session, raw_listing(seller=seller), source="api", now=NOW).listing
        _add(db_session, a, photo, tmp_path)
        _add(db_session, b, photo, tmp_path)
        db_session.refresh(b)
        assert find_reused_photos(db_session, b, max_distance=4) == []


CSV_OK = (
    "title,price,currency,brand,size,condition,url\n"
    "Stone Island hoodie,45.00,GBP,Stone Island,L,Very good,\n"
    "Moncler Maya jacket,£250,,Moncler,3,Good,https://www.vinted.co.uk/items/555000111-moncler-maya\n"
)


class TestCsvImport:
    def test_valid_rows(self, db_session):
        run, results = import_listings_csv(
            db_session, CSV_OK.encode(), source="test.csv", base_currency="GBP", now=NOW
        )
        assert run.status == "ok"
        assert (run.rows_total, run.rows_created, run.rows_failed) == (2, 2, 0)
        moncler = next(r.listing for r in results if "Moncler" in r.listing.title)
        assert moncler.external_id == "555000111"
        assert moncler.currency == "GBP"

    def test_reimport_counts_as_skipped(self, db_session):
        content = CSV_OK.replace(",\n", ",https://www.vinted.co.uk/items/444000111\n", 1)
        import_listings_csv(db_session, content.encode(), source="a", base_currency="GBP", now=NOW)
        run, _ = import_listings_csv(
            db_session, content.encode(), source="b", base_currency="GBP", now=NOW
        )
        assert run.rows_skipped == 2

    def test_bad_rows_reported_without_aborting(self, db_session):
        content = (
            "title,price,currency,listed_at\n"
            "Good row,10,GBP,\n"
            ",10,GBP,\n"
            "Bad price,ten,GBP,\n"
            "Bad date,10,GBP,yesterday\n"
            "Negative,-5,GBP,\n"
        )
        run, results = import_listings_csv(
            db_session, content.encode(), source="t", base_currency="GBP", now=NOW
        )
        assert run.status == "partial"
        assert run.rows_created == 1
        assert run.rows_failed == 4
        lines = [e["line"] for e in run.report["errors"]]
        assert lines == [3, 4, 5, 6]
        assert len(results) == 1
        assert db_session.get(IngestionRun, run.id) is not None

    def test_missing_required_column(self, db_session):
        run, _ = import_listings_csv(
            db_session, b"price\n10\n", source="t", base_currency="GBP", now=NOW
        )
        assert run.status == "failed"
        assert "title" in run.error_summary

    def test_not_utf8(self, db_session):
        run, _ = import_listings_csv(
            db_session, "title\ncafé\n".encode("latin-1"), source="t", base_currency="GBP", now=NOW
        )
        assert run.status == "failed"
        assert "UTF-8" in run.error_summary

    def test_bom_is_tolerated(self, db_session):
        run, _ = import_listings_csv(
            db_session, "﻿title\nX\n".encode(), source="t", base_currency="GBP", now=NOW
        )
        assert run.status == "ok"

    def test_row_limit(self, db_session):
        content = "title\n" + "x\n" * 5
        run, _ = import_listings_csv(
            db_session, content.encode(), source="t", base_currency="GBP", now=NOW, max_rows=3
        )
        assert run.status == "failed"
        assert run.rows_created == 0
        assert db_session.scalar(select(Listing).where(Listing.title == "x")) is None
