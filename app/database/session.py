"""Engine and session management.

One synchronous code path is shared by the API (FastAPI runs sync endpoints in a threadpool),
the Celery workers and the Telegram bot. Services receive a ``Session`` and never commit it
themselves unless documented; the caller owns the transaction (unit of work).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config.settings import Settings, get_settings


class Database:
    def __init__(self, url: str, *, pool_size: int = 5, echo: bool = False) -> None:
        self.engine: Engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=pool_size,
            max_overflow=pool_size,
            echo=echo,
        )
        _install_utc(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Database:
        settings = settings or get_settings()
        return cls(settings.database_url.get_secret_value(), pool_size=settings.database_pool_size)

    def session(self) -> Session:
        return self.session_factory()

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Transactional scope: commit on success, roll back on any exception."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()


def _install_utc(engine: Engine) -> None:
    """Force every connection to UTC so ``now()`` and date casts never depend on the host."""

    @event.listens_for(engine, "connect")
    def _set_utc(dbapi_connection, _record) -> None:  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("SET TIME ZONE 'UTC'")
        finally:
            cursor.close()


_default: Database | None = None


def get_database() -> Database:
    global _default
    if _default is None:
        _default = Database.from_settings()
    return _default


def set_database(database: Database | None) -> None:
    """Replace the process-wide database (used by tests and CLI tools)."""
    global _default
    _default = database
