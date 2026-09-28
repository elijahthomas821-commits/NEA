"""Bounded reading of multipart uploads."""

from __future__ import annotations

from fastapi import UploadFile

from app.core.errors import AppError


class PayloadTooLargeError(AppError):
    code = "payload_too_large"
    status_code = 413


def read_upload(upload: UploadFile, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` from an already-spooled upload; reject anything larger.

    Endpoints using this are plain ``def`` (run in the threadpool), so the synchronous read and
    the database work that follows never block the event loop.
    """
    data = upload.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PayloadTooLargeError(f"upload exceeds {max_bytes // 1024} KB")
    return data
