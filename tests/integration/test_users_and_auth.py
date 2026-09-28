from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import APIRouter

from app.api.deps import PrincipalDep
from app.core.errors import ConflictError
from app.core.time import utcnow
from app.services.users import (
    authenticate_api_key,
    create_api_key,
    create_user,
    revoke_api_key,
)

pytestmark = pytest.mark.integration


class TestApiKeys:
    def test_plaintext_is_not_stored(self, db_session, operator):
        plaintext, key = create_api_key(db_session, operator)
        assert plaintext.startswith("rsk_")
        assert plaintext not in key.key_hash
        assert key.key_prefix == plaintext[:12]

    def test_authenticate_valid_key(self, db_session, operator):
        plaintext, _ = create_api_key(db_session, operator)
        result = authenticate_api_key(db_session, plaintext)
        assert result is not None
        assert result[0].id == operator.id

    def test_wrong_key(self, db_session, operator):
        create_api_key(db_session, operator)
        assert authenticate_api_key(db_session, "rsk_not-a-real-key") is None

    def test_revoked_key(self, db_session, operator):
        plaintext, key = create_api_key(db_session, operator)
        revoke_api_key(db_session, key.key_prefix)
        assert authenticate_api_key(db_session, plaintext) is None

    def test_expired_key(self, db_session, operator):
        plaintext, _ = create_api_key(
            db_session, operator, expires_in_days=1, now=utcnow() - timedelta(days=2)
        )
        assert authenticate_api_key(db_session, plaintext) is None

    def test_inactive_user(self, db_session, operator):
        plaintext, _ = create_api_key(db_session, operator)
        operator.is_active = False
        assert authenticate_api_key(db_session, plaintext) is None

    def test_duplicate_user(self, db_session, operator):
        with pytest.raises(ConflictError):
            create_user(db_session, "operator")
        with pytest.raises(ConflictError):
            create_user(db_session, "someone", telegram_user_id=111)


@pytest.fixture
def protected_app(app):
    router = APIRouter()

    @router.get("/_test/whoami")
    def whoami(principal: PrincipalDep) -> dict[str, str]:
        return {"user": principal.user.username}

    app.include_router(router)
    return app


class TestApiAuth:
    def test_health_is_public(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Request-ID"]

    def test_ready_checks_database(self, client):
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["checks"]["database"] == "ok"

    def test_missing_key(self, protected_app, client):
        response = client.get("/_test/whoami")
        assert response.status_code == 401
        body = response.json()
        assert body["error"]["code"] == "unauthenticated"
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_bad_key(self, protected_app, client):
        response = client.get("/_test/whoami", headers={"Authorization": "Bearer rsk_nope"})
        assert response.status_code == 401

    def test_bearer_and_x_api_key(self, protected_app, client, api_key):
        assert client.get(
            "/_test/whoami", headers={"Authorization": f"Bearer {api_key}"}
        ).json() == {"user": "operator"}
        assert client.get("/_test/whoami", headers={"X-API-Key": api_key}).status_code == 200

    def test_rate_limit(self, protected_app, client, api_key, settings):
        protected_app.state.settings = settings.model_copy(update={"api_rate_limit_per_minute": 2})
        headers = {"X-API-Key": api_key}
        codes = [client.get("/_test/whoami", headers=headers).status_code for _ in range(3)]
        assert codes == [200, 200, 429]

    def test_request_id_is_echoed_when_safe(self, client):
        assert (
            client.get("/health", headers={"X-Request-ID": "abc12345"}).headers["X-Request-ID"]
            == "abc12345"
        )
        unsafe = client.get("/health", headers={"X-Request-ID": "<script>"})
        assert unsafe.headers["X-Request-ID"] != "<script>"

    def test_unknown_route_uses_error_envelope(self, client):
        response = client.get("/does-not-exist")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"
