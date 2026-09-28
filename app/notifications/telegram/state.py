"""Durable bot state in ``bot_state``: poll offset, processed updates, conversations.

Conversations expire (``CONVERSATION_TTL``) so a half-finished question never hijacks a
message sent hours later. Expired rows are ignored on read and pruned by the maintenance task.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import BotState

CONVERSATION_TTL = timedelta(minutes=30)
FOCUS_TTL = timedelta(hours=2)
MEDIA_GROUP_TTL = timedelta(minutes=10)
UPDATE_TTL = timedelta(days=2)
POLL_OFFSET_KEY = "poll_offset"


def get_value(session: Session, key: str, *, now: datetime) -> dict[str, Any] | None:
    row = session.get(BotState, key, populate_existing=True)
    if row is None or (row.expires_at is not None and row.expires_at <= now):
        return None
    return dict(row.value)


def set_value(
    session: Session, key: str, value: dict[str, Any], *, now: datetime, ttl: timedelta | None
) -> None:
    expires = now + ttl if ttl is not None else None
    stmt = pg_insert(BotState).values(key=key, value=value, expires_at=expires)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=[BotState.key],
            set_={"value": stmt.excluded.value, "expires_at": stmt.excluded.expires_at},
        )
    )


def delete_value(session: Session, key: str) -> None:
    session.execute(delete(BotState).where(BotState.key == key))


def claim_update(session: Session, update_id: int, *, now: datetime) -> bool:
    """True the first time an update is seen; False for a redelivery (webhook retries)."""
    stmt = (
        pg_insert(BotState)
        .values(key=f"update:{update_id}", value={}, expires_at=now + UPDATE_TTL)
        .on_conflict_do_nothing(index_elements=[BotState.key])
        .returning(BotState.key)
    )
    return session.execute(stmt).scalar_one_or_none() is not None


def get_poll_offset(session: Session) -> int | None:
    value = session.scalar(select(BotState.value).where(BotState.key == POLL_OFFSET_KEY))
    offset = (value or {}).get("offset")
    return offset if isinstance(offset, int) else None


def set_poll_offset(session: Session, offset: int, *, now: datetime) -> None:
    set_value(session, POLL_OFFSET_KEY, {"offset": offset}, now=now, ttl=None)


# --------------------------------------------------------------------------- conversations


def conversation_key(chat_id: int, user_id: int) -> str:
    return f"conv:{chat_id}:{user_id}"


def focus_key(user_id: int) -> str:
    return f"focus:{user_id}"


def media_group_key(media_group_id: str) -> str:
    return f"media:{media_group_id[:60]}"
