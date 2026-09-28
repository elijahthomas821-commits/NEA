"""Listing photo storage.

Photos are only ever *uploaded* (API multipart or Telegram) — nothing is fetched from a
marketplace or any other URL, so there is no SSRF surface and no automated access to Vinted.
Uploads are validated with Pillow (format, byte size, pixel count), content-addressed by
SHA-256, and hashed with dHash for near-duplicate detection.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.image_hash import dhash, hamming_distance
from app.core.errors import ValidationFailedError
from app.models import Listing, ListingImage

ALLOWED_FORMATS = {
    "JPEG": ("jpg", "image/jpeg"),
    "PNG": ("png", "image/png"),
    "WEBP": ("webp", "image/webp"),
}
MAX_PIXELS = 40_000_000  # far above any phone photo; blocks decompression bombs


@dataclass
class StoredImage:
    image: ListingImage
    created: bool


@dataclass(frozen=True)
class ImageInfo:
    sha256: str
    phash: str
    width: int
    height: int
    extension: str
    content_type: str


def inspect_image(data: bytes, *, max_bytes: int) -> ImageInfo:
    """Validate an upload and compute its hashes. Raises ValidationFailedError if unusable."""
    if not data:
        raise ValidationFailedError("empty image upload")
    if len(data) > max_bytes:
        raise ValidationFailedError(f"image larger than {max_bytes // (1024 * 1024)} MB")
    try:
        with Image.open(BytesIO(data)) as probe:
            fmt = probe.format or ""
            width, height = probe.size
            if fmt not in ALLOWED_FORMATS:
                raise ValidationFailedError(f"unsupported image format {fmt or 'unknown'}")
            if width * height > MAX_PIXELS:
                raise ValidationFailedError("image dimensions too large")
            probe.verify()
        with Image.open(BytesIO(data)) as image:
            image.load()
            phash = dhash(image)
    except ValidationFailedError:
        raise
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
    ) as exc:
        raise ValidationFailedError("file is not a valid image") from exc
    extension, content_type = ALLOWED_FORMATS[fmt]
    return ImageInfo(
        sha256=hashlib.sha256(data).hexdigest(),
        phash=phash,
        width=width,
        height=height,
        extension=extension,
        content_type=content_type,
    )


def storage_key_for(info: ImageInfo) -> str:
    return f"{info.sha256[:2]}/{info.sha256}.{info.extension}"


def _write_atomic(root: Path, key: str, data: bytes) -> None:
    target = root / key
    if target.exists():
        return  # content-addressed: identical bytes already stored
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".upload-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def add_listing_image(
    session: Session,
    listing: Listing,
    data: bytes,
    *,
    media_dir: Path,
    max_bytes: int,
    max_images: int,
    source: str = "upload",
    telegram_file_id: str | None = None,
    telegram_file_unique_id: str | None = None,
) -> StoredImage:
    info = inspect_image(data, max_bytes=max_bytes)
    existing = session.scalar(
        select(ListingImage).where(
            ListingImage.listing_id == listing.id, ListingImage.sha256 == info.sha256
        )
    )
    if existing is not None:
        return StoredImage(image=existing, created=False)

    count = (
        session.scalar(
            select(func.count(ListingImage.id)).where(ListingImage.listing_id == listing.id)
        )
        or 0
    )
    if count >= max_images:
        raise ValidationFailedError(f"a listing can have at most {max_images} photos")
    last_position = session.scalar(
        select(func.max(ListingImage.position)).where(ListingImage.listing_id == listing.id)
    )
    next_position = 0 if last_position is None else last_position + 1

    key = storage_key_for(info)
    _write_atomic(media_dir, key, data)
    image = ListingImage(
        listing_id=listing.id,
        position=next_position,
        source=source,
        storage_key=key,
        telegram_file_id=telegram_file_id,
        telegram_file_unique_id=telegram_file_unique_id,
        sha256=info.sha256,
        phash=info.phash,
        width=info.width,
        height=info.height,
        content_type=info.content_type,
        byte_size=len(data),
    )
    session.add(image)
    session.flush()
    return StoredImage(image=image, created=True)


def read_image(media_dir: Path, storage_key: str) -> bytes:
    path = (media_dir / storage_key).resolve()
    if media_dir.resolve() not in path.parents:
        raise ValidationFailedError("invalid storage key")
    return path.read_bytes()


def find_reused_photos(
    session: Session, listing: Listing, *, max_distance: int, scan_limit: int = 5000
) -> list[dict[str, int | str | None]]:
    """Photos of this listing that also appear on *other sellers'* listings.

    Exact hash matches use the index; near matches (re-compressed/cropped copies) are found by
    scanning the most recent ``scan_limit`` photos, which is ample for one operator's volume.
    """
    own = [img for img in listing.images if img.phash]
    if not own:
        return []
    candidates = session.execute(
        select(ListingImage.id, ListingImage.phash, Listing.id, Listing.seller_id)
        .join(Listing, Listing.id == ListingImage.listing_id)
        .where(ListingImage.listing_id != listing.id, ListingImage.phash.is_not(None))
        .order_by(ListingImage.id.desc())
        .limit(scan_limit)
    ).all()
    matches: list[dict[str, int | str | None]] = []
    for img in own:
        assert img.phash is not None
        for other_image_id, other_phash, other_listing_id, other_seller_id in candidates:
            if other_phash is None:
                continue
            if other_seller_id is not None and other_seller_id == listing.seller_id:
                continue  # the same seller re-listing is not a stolen-photo signal
            distance = hamming_distance(img.phash, other_phash)
            if distance <= max_distance:
                matches.append(
                    {
                        "image_id": img.id,
                        "other_image_id": other_image_id,
                        "other_listing_id": other_listing_id,
                        "distance": distance,
                    }
                )
    return matches
