"""Send evaluation alerts to Telegram.

Idempotent: the alert row (one per evaluation and channel) is locked while it is sent and
marked ``sent`` in the same transaction, so a retried, duplicated or redelivered task never
sends an evaluation twice. The only gap is a crash between Telegram accepting the message and
the commit, in which case the message may be sent again (at-least-once).

Failures: flood control (429) waits ``retry_after``; network errors and 5xx retry with
exponential backoff; a rejected request (unknown chat, bot blocked) fails at once; after
``max_retries`` the alert is marked ``failed``. Pending alerts that were never picked up
(lost task) are re-queued by ``notify.retry_pending``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError

from app.config.settings import Settings, get_settings
from app.core.enums import AlertMode, AlertStatus, UserDecision
from app.core.logging import get_logger
from app.core.redaction import safe_error_summary
from app.core.time import utcnow
from app.database.session import Database, get_database
from app.models import Alert, ListingEvaluation
from app.notifications.telegram.client import TelegramClient, TelegramError, TelegramRetryAfterError
from app.notifications.telegram.factory import build_telegram_client
from app.notifications.telegram.formatter import decision_keyboard, format_alert
from app.services.alerts import build_alert_view, open_alert
from app.services.config_service import ConfigService
from app.workers.celery_app import celery_app
from app.workers.dispatch import SEND_ALERT_TASK, CeleryDispatcher
from app.workers.tasks.base import AppTask

log = get_logger(__name__)

RETRY_PENDING_TASK = "notify.retry_pending"
STALE_AFTER = timedelta(minutes=10)
EXPIRE_AFTER = timedelta(days=2)


class Outcome(StrEnum):
    SENT = "sent"
    SUPPRESSED = "suppressed"
    ALREADY_DONE = "already_done"
    BUSY = "busy"  # another worker is sending it right now
    SKIPPED = "skipped"  # Telegram is not configured
    MISSING = "missing"
    RETRY = "retry"
    FAILED = "failed"


@dataclass(frozen=True)
class DeliveryResult:
    outcome: Outcome
    retry_after: int | None = None
    detail: str | None = None


def deliver_alert(
    evaluation_id: int,
    *,
    mode: AlertMode,
    database: Database,
    client: TelegramClient | None,
    settings: Settings,
    now: datetime | None = None,
) -> DeliveryResult:
    """Task body: decide, render and send one evaluation's alert."""
    now = now or utcnow()
    chat_id = settings.alert_chat_id
    if client is None or chat_id is None:
        log.info("alert_skipped", evaluation_id=evaluation_id, reason="telegram not configured")
        return DeliveryResult(Outcome.SKIPPED)

    with database.session_scope() as session:
        evaluation = session.get(ListingEvaluation, evaluation_id)
        if evaluation is None:
            return DeliveryResult(Outcome.MISSING)
        rules = ConfigService(session).bundle().deal_rules.realert
        alert, plan = open_alert(session, evaluation, mode=mode, chat_id=chat_id, rules=rules)
        if alert is None:
            return DeliveryResult(Outcome.BUSY)
        if plan is not None and not plan.send:
            log.info("alert_suppressed", evaluation_id=evaluation_id, reason=plan.reason)
            return DeliveryResult(Outcome.SUPPRESSED, detail=plan.reason)
        if alert.status != AlertStatus.PENDING.value:
            return DeliveryResult(Outcome.ALREADY_DONE, detail=alert.status)

        view = build_alert_view(session, evaluation, now=now, base_currency=settings.base_currency)
        chosen = UserDecision(alert.user_decision) if alert.user_decision else None
        target = alert.chat_id or chat_id
        alert.attempts += 1
        try:
            message = client.send_message(
                target,
                format_alert(view),
                reply_markup=decision_keyboard(alert.id, chosen=chosen, url=view.url),
            )
        except TelegramError as exc:
            alert.last_error = safe_error_summary(exc, limit=500)
            if exc.retryable:
                retry_after = exc.retry_after if isinstance(exc, TelegramRetryAfterError) else None
                log.warning("alert_send_retry", evaluation_id=evaluation_id, error=alert.last_error)
                return DeliveryResult(Outcome.RETRY, retry_after=retry_after)
            alert.status = AlertStatus.FAILED.value
            log.error("alert_send_failed", evaluation_id=evaluation_id, error=alert.last_error)
            return DeliveryResult(Outcome.FAILED, detail=alert.last_error)

        alert.status = AlertStatus.SENT.value
        alert.sent_at = now
        alert.chat_id = target
        alert.external_message_id = message.get("message_id")
        alert.last_error = None
        log.info("alert_sent", evaluation_id=evaluation_id, alert_id=alert.id)
        return DeliveryResult(Outcome.SENT)


def mark_alert_failed(database: Database, evaluation_id: int, error: str) -> None:
    with database.session_scope() as session:
        session.execute(
            update(Alert)
            .where(
                Alert.evaluation_id == evaluation_id,
                Alert.status == AlertStatus.PENDING.value,
            )
            .values(status=AlertStatus.FAILED.value, last_error=error[:500])
        )


def retry_countdown(retries: int, retry_after: int | None) -> int:
    if retry_after is not None:
        return retry_after + 1
    backoff: int = min(600, 10 * 2 ** min(retries, 10))
    return backoff + secrets.randbelow(6)


@celery_app.task(
    name=SEND_ALERT_TASK,
    base=AppTask,
    bind=True,
    autoretry_for=(OperationalError,),
    max_retries=8,
)
def send_alert_task(
    self: AppTask,
    evaluation_id: int,
    alert: str = AlertMode.ALWAYS.value,
    correlation_id: str | None = None,
) -> str:
    settings = get_settings()
    client = build_telegram_client(settings)
    try:
        result = deliver_alert(
            evaluation_id,
            mode=AlertMode(alert),
            database=get_database(),
            client=client,
            settings=settings,
        )
    finally:
        if client is not None:
            client.close()
    if result.outcome is Outcome.RETRY:
        if self.request.retries >= (self.max_retries or 0):
            mark_alert_failed(
                get_database(), evaluation_id, "gave up after repeated Telegram failures"
            )
            return Outcome.FAILED.value
        raise self.retry(countdown=retry_countdown(self.request.retries, result.retry_after))
    return result.outcome.value


# --------------------------------------------------------------------------- stuck alerts


def requeue_pending_alerts(database: Database, *, now: datetime, limit: int = 50) -> list[int]:
    """Evaluation IDs of alerts stuck in ``pending``; very old ones are marked failed."""
    with database.session_scope() as session:
        session.execute(
            update(Alert)
            .where(
                Alert.status == AlertStatus.PENDING.value,
                Alert.created_at < now - EXPIRE_AFTER,
            )
            .values(status=AlertStatus.FAILED.value, last_error="expired before it could be sent")
        )
        rows = session.scalars(
            select(Alert.evaluation_id)
            .where(
                Alert.status == AlertStatus.PENDING.value,
                Alert.updated_at < now - STALE_AFTER,
            )
            .order_by(Alert.id)
            .limit(limit)
        )
        return list(rows)


@celery_app.task(name=RETRY_PENDING_TASK, base=AppTask, bind=True)
def retry_pending_alerts_task(self: AppTask, correlation_id: str | None = None) -> int:
    evaluation_ids = requeue_pending_alerts(get_database(), now=utcnow())
    dispatcher = CeleryDispatcher()
    for evaluation_id in evaluation_ids:
        # The alert row already exists, so the mode is not re-applied.
        dispatcher.send_alert(evaluation_id, alert=AlertMode.ALWAYS)
    if evaluation_ids:
        log.info("requeued_pending_alerts", count=len(evaluation_ids))
    return len(evaluation_ids)
