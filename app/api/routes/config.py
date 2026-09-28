"""Versioned business configuration (fees, thresholds, multipliers, price guide)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body

from app.api.deps import PrincipalDep, SessionDep
from app.core.enums import ConfigKind
from app.models import ConfigVersion
from app.services.config_service import ConfigService

router = APIRouter(prefix="/config", tags=["config"])


def _version_out(row: ConfigVersion, *, include_payload: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row.id,
        "kind": row.kind,
        "version": row.version,
        "is_active": row.is_active,
        "note": row.note,
        "created_at": row.created_at,
        "created_by": row.created_by,
    }
    if include_payload:
        out["payload"] = row.payload
    return out


@router.get("")
def list_active(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    service = ConfigService(session)
    return {kind.value: _version_out(service.active_row(kind)) for kind in ConfigKind}


@router.get("/{kind}")
def get_active(kind: ConfigKind, principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    return _version_out(ConfigService(session).active_row(kind), include_payload=True)


@router.put("/{kind}")
def put_config(
    kind: ConfigKind,
    principal: PrincipalDep,
    session: SessionDep,
    payload: Annotated[dict[str, Any], Body(description="the complete configuration payload")],
    note: str | None = None,
) -> dict[str, Any]:
    """Create a new version (validated). Past evaluations keep referring to the old one."""
    row, created = ConfigService(session).create_version(
        kind, payload, actor=principal.actor, note=note
    )
    session.commit()
    return {**_version_out(row, include_payload=True), "created": created}


@router.get("/{kind}/versions")
def versions(
    kind: ConfigKind, principal: PrincipalDep, session: SessionDep
) -> list[dict[str, Any]]:
    return [_version_out(row) for row in ConfigService(session).list_versions(kind)]


@router.post("/{kind}/versions/{version}/activate")
def activate(
    kind: ConfigKind, version: int, principal: PrincipalDep, session: SessionDep
) -> dict[str, Any]:
    row = ConfigService(session).activate_version(kind, version, actor=principal.actor)
    session.commit()
    return _version_out(row, include_payload=True)
