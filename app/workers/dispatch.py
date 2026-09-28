"""How the API and bot hand work to background tasks.

``CeleryDispatcher`` enqueues onto Redis (production). ``InlineDispatcher`` runs the same task
functions synchronously in-process (tests, and the ``sync=true`` API option). Callers must
commit their transaction *before* dispatching so the worker sees the data.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.core.logging import get_logger

log = get_logger(__name__)

EVALUATE_TASK = "evaluate.listing"
SEND_ALERT_TASK = "notify.send_alert"


class TaskDispatcher(Protocol):
    def evaluate_listing(
        self, listing_id: int, *, trigger: str, notify: bool, correlation_id: str | None = None
    ) -> None: ...

    def send_alert(self, evaluation_id: int, *, correlation_id: str | None = None) -> None: ...


class CeleryDispatcher:
    """Sends tasks by name, so callers never import worker modules."""

    def evaluate_listing(
        self, listing_id: int, *, trigger: str, notify: bool, correlation_id: str | None = None
    ) -> None:
        from app.workers.celery_app import celery_app

        celery_app.send_task(
            EVALUATE_TASK,
            kwargs={
                "listing_id": listing_id,
                "trigger": trigger,
                "notify": notify,
                "correlation_id": correlation_id,
            },
        )

    def send_alert(self, evaluation_id: int, *, correlation_id: str | None = None) -> None:
        from app.workers.celery_app import celery_app

        celery_app.send_task(
            SEND_ALERT_TASK,
            kwargs={"evaluation_id": evaluation_id, "correlation_id": correlation_id},
        )


@dataclass
class RecordingDispatcher:
    """Records calls without running anything (unit tests)."""

    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def evaluate_listing(
        self, listing_id: int, *, trigger: str, notify: bool, correlation_id: str | None = None
    ) -> None:
        self.calls.append(
            ("evaluate_listing", {"listing_id": listing_id, "trigger": trigger, "notify": notify})
        )

    def send_alert(self, evaluation_id: int, *, correlation_id: str | None = None) -> None:
        self.calls.append(("send_alert", {"evaluation_id": evaluation_id}))


@dataclass
class InlineDispatcher:
    """Runs task bodies immediately in the calling process."""

    evaluate: Callable[..., Any]
    notify: Callable[..., Any] | None = None

    def evaluate_listing(
        self, listing_id: int, *, trigger: str, notify: bool, correlation_id: str | None = None
    ) -> None:
        self.evaluate(listing_id=listing_id, trigger=trigger, notify=notify, dispatcher=self)

    def send_alert(self, evaluation_id: int, *, correlation_id: str | None = None) -> None:
        if self.notify is None:
            log.info("inline_dispatcher_no_notifier", evaluation_id=evaluation_id)
            return
        self.notify(evaluation_id=evaluation_id)
