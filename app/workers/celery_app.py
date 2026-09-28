"""Celery application.

Reliability settings: tasks are acknowledged only after they finish (``acks_late``) and are
re-queued if a worker dies mid-task (``task_reject_on_worker_lost``), so every task must be
idempotent. Tasks that exhaust their retries are written to ``task_failures`` (dead letters).
"""

from __future__ import annotations

from celery import Celery
from celery.signals import worker_process_init

from app.config.settings import get_settings
from app.core.logging import configure_logging
from app.workers.beat_schedule import BEAT_SCHEDULE

TASK_MODULES = [
    "app.workers.tasks.maintenance",
]


def create_celery() -> Celery:
    settings = get_settings()
    broker = settings.redis_url.get_secret_value()
    app = Celery("resale", broker=broker, include=TASK_MODULES)
    app.conf.update(
        task_ignore_result=True,
        result_backend=None,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        broker_connection_retry_on_startup=True,
        task_time_limit=300,
        task_soft_time_limit=240,
        worker_hijack_root_logger=False,
        worker_redirect_stdouts=False,
        beat_schedule=BEAT_SCHEDULE,
        # Visibility timeout must exceed the longest task + retry countdown.
        broker_transport_options={"visibility_timeout": 3600},
    )
    return app


celery_app = create_celery()


@worker_process_init.connect
def _init_worker_logging(**_kwargs: object) -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
