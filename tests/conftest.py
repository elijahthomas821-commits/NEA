"""Shared fixtures.

Integration tests run against a real PostgreSQL database (``TEST_DATABASE_URL``). The schema is
rebuilt once per session by running the Alembic migrations, reference data is seeded once, and
every test runs inside a transaction that is rolled back afterwards (SAVEPOINT mode), so tests
are isolated and fast.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.orm import Session

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("LOG_FORMAT", "console")
os.environ.setdefault("AI_ENABLED", "false")

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://resale:resale@127.0.0.1:5432/resale_test"
)
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://127.0.0.1:6379/15")
ROOT = Path(__file__).resolve().parents[1]


def alembic_config(connection: Connection | None = None) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def reset_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    eng = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    try:
        try:
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception as exc:  # pragma: no cover - environment problem
            pytest.skip(f"PostgreSQL not available at TEST_DATABASE_URL: {exc}")
        reset_schema(eng)
        with eng.begin() as conn:
            command.upgrade(alembic_config(conn), "head")

        from app.services.seed import seed_reference_data

        with Session(bind=eng) as session:
            seed_reference_data(session)
            session.commit()
        yield eng
    finally:
        eng.dispose()


class TestDatabase:
    """Stands in for :class:`app.database.session.Database`, bound to one test connection."""

    __test__ = False

    def __init__(self, engine: Engine, connection: Connection) -> None:
        self.engine = engine
        self.connection = connection

    def session(self) -> Session:
        return Session(
            bind=self.connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        )

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        session = self.session()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:  # pragma: no cover - interface parity
        pass


@pytest.fixture
def db_connection(engine: Engine) -> Iterator[Connection]:
    connection = engine.connect()
    transaction = connection.begin()
    try:
        yield connection
    finally:
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def test_db(engine: Engine, db_connection: Connection) -> Iterator[TestDatabase]:
    from app.database import session as session_module

    database = TestDatabase(engine, db_connection)
    previous = session_module._default
    session_module.set_database(database)  # type: ignore[arg-type]
    try:
        yield database
    finally:
        session_module.set_database(previous)


@pytest.fixture
def db_session(test_db: TestDatabase) -> Iterator[Session]:
    session = test_db.session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def settings(tmp_path: Path):
    from app.config.settings import Settings

    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        app_env="test",
        log_format="console",
        database_url=TEST_DATABASE_URL,
        redis_url=TEST_REDIS_URL,
        ai_enabled=False,
        telegram_bot_token=None,
        telegram_allowed_user_ids=[111],
        media_dir=tmp_path / "media",
    )


@pytest.fixture
def config_bundle(db_session: Session):
    from app.services.config_service import ConfigService

    return ConfigService(db_session).bundle()
