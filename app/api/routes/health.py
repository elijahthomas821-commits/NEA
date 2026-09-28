"""Liveness and readiness probes (unauthenticated, reveal nothing sensitive)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import __version__

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/health/ready")
def ready(request: Request) -> JSONResponse:
    checks: dict[str, Any] = {}
    healthy = True
    try:
        with request.app.state.database.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"
        healthy = False

    probe = getattr(request.app.state, "redis_probe", None)
    if probe is not None:
        try:
            probe()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "unavailable"
            healthy = False

    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ok" if healthy else "degraded", "checks": checks},
    )
