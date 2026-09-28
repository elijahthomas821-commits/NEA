"""Perceptual image hashing (difference hash) for spotting reused photos.

The same photo appearing on listings from different sellers is a classic sign of stock or
stolen images. dHash survives re-compression and resizing; the Hamming distance between two
hashes measures how different the images look (0 = visually identical).
"""

from __future__ import annotations

from PIL import Image, ImageOps

HASH_SIZE = 8  # 8x8 = 64-bit hash


def dhash(image: Image.Image, hash_size: int = HASH_SIZE) -> str:
    """64-bit difference hash as 16 lowercase hex characters."""
    upright = ImageOps.exif_transpose(image) or image
    gray = upright.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    pixels = gray.tobytes()
    width = hash_size + 1
    bits = 0
    for row in range(hash_size):
        offset = row * width
        for col in range(hash_size):
            bits = (bits << 1) | (1 if pixels[offset + col] > pixels[offset + col + 1] else 0)
    return f"{bits:0{hash_size * hash_size // 4}x}"


def hamming_distance(a: str, b: str) -> int:
    return (int(a, 16) ^ int(b, 16)).bit_count()


def is_near_duplicate(a: str, b: str, max_distance: int) -> bool:
    return hamming_distance(a, b) <= max_distance
