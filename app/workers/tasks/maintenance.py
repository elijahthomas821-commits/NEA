"""Housekeeping tasks."""

from __future__ import annotations

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.time import utcnow
from app.database.session import get_database
from app.models import BotState
from app.workers.celery_app import celery_app
from app.workers.tasks.base import AppTask

log = get_logger(__name__)


def prune_expired_state(session: Session) -> int:
    result = session.execute(
        delete(BotState).where(BotState.expires_at.is_not(None), BotState.expires_at < utcnow())
    )
    return int(getattr(result, "rowcount", 0) or 0)


@celery_app.task(name="maintenance.prune_expired_state", base=AppTask, bind=True)
def prune_expired_state_task(self: AppTask, correlation_id: str | None = None) -> int:
    with get_database().session_scope() as session:
        removed = prune_expired_state(session)
    log.info("pruned_bot_state", removed=removed)
    return removed
