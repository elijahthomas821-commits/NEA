"""Periodic tasks (Celery beat). Times are UTC."""

from __future__ import annotations

from typing import Any

from celery.schedules import crontab

BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "recompute-market-statistics": {
        "task": "market.recompute_statistics",
        "schedule": crontab(hour=3, minute=17),
    },
    "prune-expired-state": {
        "task": "maintenance.prune_expired_state",
        "schedule": crontab(hour=4, minute=7),
    },
}
