"""Evaluate a listing in the background, then (optionally) queue its alert."""

from __future__ import annotations

from sqlalchemy.exc import OperationalError

from app.core.enums import AlertMode
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.database.session import get_database
from app.services.pipeline import evaluate_listing_by_id
from app.workers.celery_app import celery_app
from app.workers.dispatch import EVALUATE_TASK, CeleryDispatcher, TaskDispatcher
from app.workers.tasks.base import AppTask

log = get_logger(__name__)


def run_evaluation(
    listing_id: int,
    *,
    trigger: str,
    alert: AlertMode | str = AlertMode.OFF,
    dispatcher: TaskDispatcher | None = None,
    correlation_id: str | None = None,
) -> int | None:
    """Task body, also used in-process by InlineDispatcher."""
    try:
        with get_database().session_scope() as session:
            evaluation = evaluate_listing_by_id(session, listing_id, trigger=trigger)
            evaluation_id = evaluation.id
    except NotFoundError:
        log.warning("evaluate_listing_missing", listing_id=listing_id)
        return None
    mode = AlertMode(alert)
    if mode is not AlertMode.OFF and dispatcher is not None:
        dispatcher.send_alert(evaluation_id, alert=mode, correlation_id=correlation_id)
    return evaluation_id


@celery_app.task(
    name=EVALUATE_TASK,
    base=AppTask,
    bind=True,
    autoretry_for=(OperationalError,),
    max_retries=5,
)
def evaluate_listing_task(
    self: AppTask,
    listing_id: int,
    trigger: str = "ingest",
    alert: str = AlertMode.ALWAYS.value,
    correlation_id: str | None = None,
) -> int | None:
    return run_evaluation(
        listing_id,
        trigger=trigger,
        alert=alert,
        dispatcher=CeleryDispatcher(),
        correlation_id=correlation_id,
    )
