from datetime import UTC, datetime
from decimal import Decimal
from io import BytesIO

import pytest
from PIL import Image
from pydantic import ValidationError

from app.analysis.image_hash import dhash, hamming_distance, is_near_duplicate
from app.collectors.base import AdapterPage, RawListing, RawSale
from tests.factories import image_bytes, raw_listing


class TestRawListing:
    def test_price_requires_currency(self):
        with pytest.raises(ValidationError, match="currency is required"):
            raw_listing(price=Decimal("10"), currency=None)

    def test_missing_price_is_allowed(self):
        assert raw_listing(price=None, currency=None).price is None

    def test_blank_strings_become_none(self):
        listing = raw_listing(raw_brand="  ", description="")
        assert listing.raw_brand is None
        assert listing.description is None

    def test_currency_normalised(self):
        assert raw_listing(currency="gbp").currency == "GBP"

    @pytest.mark.parametrize("price", [Decimal("0"), Decimal("-1"), Decimal("1.234")])
    def test_invalid_prices(self, price):
        with pytest.raises(ValidationError):
            raw_listing(price=price)

    def test_unknown_fields_rejected(self):
        with pytest.raises(ValidationError):
            RawListing(marketplace="vinted", external_id="1", title="x", colour="red")  # type: ignore[call-arg]

    def test_generic_page(self):
        page = AdapterPage[RawListing](items=[raw_listing()])
        assert len(page.items) == 1


class TestRawSale:
    def test_dates_ordered(self):
        with pytest.raises(ValidationError, match="listed_at"):
            RawSale(
                source="manual_entry",
                brand="stone-island",
                category="sweatshirts",
                sale_price=Decimal("80"),
                currency="GBP",
                listed_at=datetime(2026, 5, 2, tzinfo=UTC),
                sold_at=datetime(2026, 5, 1, tzinfo=UTC),
            )


class TestImageHash:
    def _open(self, data: bytes) -> Image.Image:
        return Image.open(BytesIO(data))

    def test_hash_format(self):
        value = dhash(self._open(image_bytes(seed=1)))
        assert len(value) == 16
        int(value, 16)

    def test_resized_and_recompressed_copy_is_near_duplicate(self):
        original = self._open(image_bytes(seed=3, size=(640, 480)))
        smaller = original.resize((320, 240))
        buffer = BytesIO()
        smaller.save(buffer, format="JPEG", quality=60)
        copy = self._open(buffer.getvalue())
        assert hamming_distance(dhash(original), dhash(copy)) <= 4

    def test_different_images_differ(self):
        a = dhash(self._open(image_bytes(seed=1)))
        b = dhash(self._open(image_bytes(seed=9)))
        assert not is_near_duplicate(a, b, 4)

    def test_hamming(self):
        assert hamming_distance("0000000000000000", "000000000000000f") == 4
