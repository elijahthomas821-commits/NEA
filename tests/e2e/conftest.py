"""End-to-end tests reuse the integration fixtures (database, API app and client, bot)."""

from tests.integration.conftest import (  # noqa: F401 - pytest fixtures
    api_key,
    app,
    auth_client,
    bot,
    client,
    dispatcher,
    files,
    operator,
    recorder,
)
