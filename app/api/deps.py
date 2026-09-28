"""FastAPI dependencies: database session, authentication, rate limiting, dispatcher."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.config.settings import Settings
from app.core.errors import AppError, AuthenticationError
from app.database.session import Database
from app.models import ApiKey, User
from app.services.audit import Actor
from app.services.users import authenticate_api_key
from app.workers.dispatch import TaskDispatcher


class RateLimitedError(AppError):
    code = "rate_limited"
    status_code = 429


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_db(request: Request) -> Database:
    database: Database = request.app.state.database
    return database


def get_session(request: Request) -> Iterator[Session]:
    """A session per request. Routes commit explicitly; anything uncommitted is rolled back."""
    session = get_db(request).session()
    try:
        yield session
    finally:
        if session.in_transaction():
            session.rollback()
        session.close()


def get_dispatcher(request: Request) -> TaskDispatcher:
    dispatcher: TaskDispatcher = request.app.state.dispatcher
    return dispatcher


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DispatcherDep = Annotated[TaskDispatcher, Depends(get_dispatcher)]


@dataclass(frozen=True)
class Principal:
    user: User
    api_key: ApiKey

    @property
    def actor(self) -> Actor:
        return Actor(user_id=self.user.id, label=f"api:{self.api_key.key_prefix}")


def _extract_token(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            return token.strip()
    return None


def require_principal(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
) -> Principal:
    token = _extract_token(authorization, x_api_key)
    if not token:
        raise AuthenticationError("missing API key")
    result = authenticate_api_key(session, token)
    if result is None:
        raise AuthenticationError("invalid or expired API key")
    user, key = result
    if session.dirty:
        session.commit()  # persist last_used_at
    limiter = request.app.state.rate_limiter
    if not limiter.hit(f"key:{key.id}", settings.api_rate_limit_per_minute):
        raise RateLimitedError("rate limit exceeded; try again in a minute")
    return Principal(user=user, api_key=key)


PrincipalDep = Annotated[Principal, Depends(require_principal)]
