"""Shared task base: correlation IDs, database sessions and dead-letter recording."""

from __future__ import annotations

from typing import Any

from celery import Task

from app.core.logging import bind_correlation_id, clear_context, get_logger
from app.core.redaction import redact_value, safe_error_summary
from app.database.session import get_database
from app.models import TaskFailure

log = get_logger(__name__)


class AppTask(Task):  # type: ignore[type-arg]
    """Base class for all tasks.

    * Retries use exponential backoff with jitter (per-task ``autoretry_for``).
    * A task that finally fails is recorded in ``task_failures`` with a redacted error.
    """

    abstract = True
    max_retries = 5
    retry_backoff = True
    retry_backoff_max = 600
    retry_jitter = True

    def before_start(self, task_id: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        clear_context()
        bind_correlation_id(kwargs.get("correlation_id") or task_id)

    def on_failure(
        self,
        exc: BaseException,
        task_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        einfo: Any,
    ) -> None:
        log.error("task_failed", task=self.name, task_id=task_id, error=safe_error_summary(exc))
        try:
            with get_database().session_scope() as session:
                session.add(
                    TaskFailure(
                        task_name=self.name,
                        task_id=task_id,
                        args=redact_value({"args": list(args), "kwargs": kwargs}),
                        error=safe_error_summary(exc, limit=1000),
                        retries=self.request.retries or 0,
                    )
                )
        except Exception as record_exc:  # never mask the original failure
            log.error("dead_letter_write_failed", error=safe_error_summary(record_exc))
