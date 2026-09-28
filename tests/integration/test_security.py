"""Security review checks on the running API."""

from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.integration

# Everything else must reject a request without an API key.
PUBLIC = {
    ("GET", "/health"),
    ("GET", "/health/ready"),
    ("POST", "/telegram/webhook"),  # authenticated by Telegram's secret header instead
}


def routes(app):
    """Every operation in the API schema, plus the webhook (hidden from the schema)."""
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            yield method.upper(), path
    yield "POST", "/telegram/webhook"


def concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


def test_every_route_requires_an_api_key(app, client):
    checked = 0
    for method, path in routes(app):
        if (method, path) in PUBLIC:
            continue
        response = client.request(method, concrete(path), json={})
        assert response.status_code == 401, f"{method} {path} -> {response.status_code}"
        assert response.json()["error"]["code"] == "unauthenticated"
        checked += 1
    assert checked >= 40  # the sweep really covered the API


def test_public_routes_need_no_key(app, client):
    assert {r for r in routes(app) if r in PUBLIC} == PUBLIC
    assert client.get("/health").status_code == 200
    # Polling mode: the webhook does not exist; in webhook mode it checks Telegram's secret.
    assert client.post("/telegram/webhook", json={}).status_code == 404


def test_invalid_and_malformed_keys(client):
    for header in (
        {"Authorization": "Bearer rsk_not_a_real_key"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"X-API-Key": ""},
        {"Authorization": "Bearer " + "x" * 5000},
    ):
        assert client.get("/listings", headers=header).status_code == 401


def test_security_headers(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert "X-Request-ID" in response.headers


def test_unhandled_errors_reveal_nothing(app, auth_client, monkeypatch):
    from app.api.routes import listings

    def boom(*args, **kwargs):
        raise RuntimeError("database password is hunter2")

    monkeypatch.setattr(listings, "raw_listing_from_text", boom)
    response = auth_client.post("/listings/quick", json={"text": "anything"})
    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "internal_error",
        "message": "internal server error",
        "request_id": response.headers["X-Request-ID"],
    }
    assert "hunter2" not in response.text


def test_oversized_bodies_are_refused_before_parsing(auth_client, app):
    limit = app.state.settings.max_request_bytes
    response = auth_client.post(
        "/listings", content=b"{}", headers={"Content-Length": str(limit + 1)}
    )
    assert response.status_code == 413
