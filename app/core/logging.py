"""Structured logging (structlog) with mandatory secret redaction and correlation IDs.

All stdlib loggers (uvicorn, celery, httpx, sqlalchemy) are routed through the same processor
chain, so a Bot API URL logged by httpx is redacted exactly like our own events.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Literal

import structlog
from structlog.tracebacks import ExceptionDictTransformer

from app.core.redaction import redact_processor

LogFormat = Literal["json", "console"]

_configured = False


def _shared_processors() -> list[Any]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.ExtraAdder(),
    ]


def configure_logging(level: str = "INFO", fmt: LogFormat = "json") -> None:
    """Configure structlog + stdlib logging. Safe to call more than once."""
    global _configured

    exception_renderer: Any
    if fmt == "json":
        # show_locals=False: local variables can hold secrets and personal data.
        exception_renderer = structlog.processors.ExceptionRenderer(
            ExceptionDictTransformer(show_locals=False)
        )
        renderer: Any = structlog.processors.JSONRenderer(sort_keys=False, default=str)
    else:
        exception_renderer = structlog.processors.format_exc_info
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    # Redaction runs after exceptions are rendered to text/dicts so tracebacks are scrubbed too.
    pre_render: list[Any] = [
        *_shared_processors(),
        structlog.processors.StackInfoRenderer(),
        exception_renderer,
        redact_processor,
    ]

    structlog.configure(
        processors=[*pre_render, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=pre_render,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Noisy libraries: keep warnings, drop per-request chatter.
    for name in ("httpx", "httpcore", "anthropic", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)

    _configured = True


def get_logger(name: str | None = None) -> Any:
    return structlog.get_logger(name)


def bind_correlation_id(correlation_id: str) -> None:
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()
