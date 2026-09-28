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


@pytest.fixture
def recorder(db_session, config_bundle):
    """Record a comparable sale through the real service."""
    from app.services.audit import Actor
    from app.services.catalogue import load_catalogue
    from app.services.market_data import record_sale

    catalogue = load_catalogue(db_session)

    def record(sale):
        return record_sale(
            db_session,
            sale,
            catalogue=catalogue,
            identification=config_bundle.identification,
            sizes=config_bundle.sizes,
            actor=Actor.system("test"),
        )

    return record


@pytest.fixture
def files():
    from tests.factories import image_bytes
    from tests.telegram_updates import FakeFiles

    return FakeFiles({f"p{i}": image_bytes(seed=i) for i in range(1, 5)})


@pytest.fixture
def bot(settings, test_db, db_session, files):
    """The Telegram handler with a fixed clock, driven like the real bot."""
    from app.notifications.telegram.handlers import BotHandler
    from tests.telegram_updates import BOT_NOW, Harness

    return Harness(BotHandler(settings, files, clock=lambda: BOT_NOW), test_db, db_session)
