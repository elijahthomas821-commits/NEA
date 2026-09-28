"""Test data builders."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime
from decimal import Decimal
from io import BytesIO
from typing import Any

from PIL import Image, ImageDraw

from app.collectors.base import RawListing, RawSeller

_ids = itertools.count(1)
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def next_id(prefix: str = "") -> str:
    return f"{prefix}{next(_ids):08d}"


def raw_listing(**overrides: Any) -> RawListing:
    data: dict[str, Any] = {
        "marketplace": "vinted",
        "external_id": next_id("9"),
        "url": None,
        "title": "Stone Island garment dyed crewneck sweatshirt navy",
        "raw_brand": "Stone Island",
        "raw_category": "Sweatshirts",
        "raw_size": "L",
        "raw_colour": "Navy",
        "raw_condition": "Very good",
        "price": Decimal("45.00"),
        "currency": "GBP",
    }
    data.update(overrides)
    return RawListing(**data)


def raw_seller(**overrides: Any) -> RawSeller:
    data: dict[str, Any] = {
        "external_seller_id": next_id("s"),
        "username": "seller",
        "rating": Decimal("4.9"),
        "review_count": 120,
    }
    data.update(overrides)
    return RawSeller(**data)


def image_bytes(
    *,
    seed: int = 0,
    size: tuple[int, int] = (320, 240),
    fmt: str = "JPEG",
) -> bytes:
    """A deterministic, structured test image (different seeds look different)."""
    image = Image.new("RGB", size, (20 + seed * 37 % 200, 60, 90))
    draw = ImageDraw.Draw(image)
    width, height = size
    for i in range(6):
        x0 = (seed * 53 + i * 41) % max(width - 40, 1)
        y0 = (seed * 29 + i * 67) % max(height - 40, 1)
        shade = (seed * 71 + i * 90) % 255
        draw.rectangle(
            [x0, y0, x0 + 30 + i * 5, y0 + 25 + i * 3], fill=(shade, 255 - shade, i * 40)
        )
    buffer = BytesIO()
    image.save(buffer, format=fmt, quality=90)
    return buffer.getvalue()
