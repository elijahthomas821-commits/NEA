from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.ratelimit import InMemoryRateLimiter
from app.main import create_app
from app.services.users import create_api_key, create_user
from app.workers.dispatch import RecordingDispatcher

pytestmark = pytest.mark.integration


@pytest.fixture
def dispatcher() -> RecordingDispatcher:
    return RecordingDispatcher()


@pytest.fixture
def app(settings, test_db, dispatcher):
    return create_app(
        settings,
        database=test_db,  # type: ignore[arg-type]
        dispatcher=dispatcher,
        rate_limiter=InMemoryRateLimiter(),
        configure_logs=False,
    )


@pytest.fixture
def client(app):
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def operator(db_session):
    user = create_user(db_session, "operator", telegram_user_id=111)
    db_session.commit()
    return user


@pytest.fixture
def api_key(db_session, operator) -> str:
    plaintext, _ = create_api_key(db_session, operator)
    db_session.commit()
    return plaintext


@pytest.fixture
def auth_client(client, api_key):
    client.headers["Authorization"] = f"Bearer {api_key}"
    return client
