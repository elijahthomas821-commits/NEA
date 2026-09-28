"""Migrations: upgrade → downgrade → upgrade, and no drift between models and migrations."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from app.models import Base
from tests.conftest import TEST_DATABASE_URL, alembic_config, reset_schema

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def scratch_engine():
    """A separate database so the migration round-trip cannot disturb other tests."""
    url = make_url(TEST_DATABASE_URL)
    scratch_name = f"{url.database}_migrations"
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        exists = conn.scalar(
            text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": scratch_name}
        )
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{scratch_name}"'))
    admin.dispose()
    engine = create_engine(url.set(database=scratch_name))
    reset_schema(engine)
    yield engine
    engine.dispose()


def test_upgrade_downgrade_upgrade(scratch_engine):
    with scratch_engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")
    assert "listings" in inspect(scratch_engine).get_table_names()

    with scratch_engine.begin() as conn:
        command.downgrade(alembic_config(conn), "base")
    remaining = set(inspect(scratch_engine).get_table_names()) - {"alembic_version"}
    assert remaining == set()

    with scratch_engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")
    assert "listings" in inspect(scratch_engine).get_table_names()


def test_models_match_migrations(engine):
    with engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(context, Base.metadata)
    assert diff == [], f"models and migrations differ: {diff}"
