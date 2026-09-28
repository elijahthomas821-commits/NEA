"""Audit trail for changes to money records and configuration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from app.core.redaction import redact_value
from app.models import AuditLog


@dataclass(frozen=True)
class Actor:
    """Who performed an action: a user (via API key or Telegram) or the system."""

    user_id: int | None
    label: str

    @classmethod
    def system(cls, label: str = "system") -> Actor:
        return cls(user_id=None, label=label)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    return value


def snapshot(obj: Any, fields: list[str]) -> dict[str, Any]:
    """Selected attributes of an ORM object as JSON-safe values."""
    return {field: _jsonable(getattr(obj, field, None)) for field in fields}


def record(
    session: Session,
    actor: Actor,
    *,
    action: str,
    entity_type: str,
    entity_id: int | str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_user_id=actor.user_id,
        actor_label=actor.label[:100],
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        before=redact_value(_jsonable(before)) if before is not None else None,
        after=redact_value(_jsonable(after)) if after is not None else None,
    )
    session.add(entry)
    return entry
