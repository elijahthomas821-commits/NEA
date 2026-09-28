"""Nightly market statistics recompute."""

from __future__ import annotations

from app.config.settings import get_settings
from app.core.logging import get_logger
from app.core.time import utcnow
from app.database.session import get_database
from app.services.config_service import ConfigService
from app.services.market_stats import recompute_market_statistics
from app.workers.celery_app import celery_app
from app.workers.tasks.base import AppTask

log = get_logger(__name__)


@celery_app.task(name="market.recompute_statistics", base=AppTask, bind=True)
def recompute_statistics_task(self: AppTask, correlation_id: str | None = None) -> int:
    with get_database().session_scope() as session:
        cfg = ConfigService(session).bundle().market
        rows = recompute_market_statistics(
            session, now=utcnow(), cfg=cfg, currency=get_settings().base_currency
        )
    log.info("market_statistics_recomputed", rows=rows)
    return rows
