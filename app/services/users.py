"""Users and API keys (single-operator system; the Telegram allowlist is in settings)."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError
from app.core.ids import generate_api_key, hash_api_key
from app.core.time import utcnow
from app.models import ApiKey, User
from app.services import audit
from app.services.audit import Actor

LAST_USED_WRITE_INTERVAL = timedelta(minutes=5)


def create_user(
    session: Session, username: str, *, telegram_user_id: int | None = None, role: str = "owner"
) -> User:
    username = username.strip()
    if not username:
        raise ConflictError("username must not be empty")
    if session.scalar(select(User.id).where(User.username == username)) is not None:
        raise ConflictError(f"user {username!r} already exists")
    if telegram_user_id is not None and (
        session.scalar(select(User.id).where(User.telegram_user_id == telegram_user_id)) is not None
    ):
        raise ConflictError("that Telegram account is already linked to a user")
    user = User(username=username, telegram_user_id=telegram_user_id, role=role)
    session.add(user)
    session.flush()
    audit.record(
        session,
        Actor.system("cli"),
        action="user.create",
        entity_type="user",
        entity_id=user.id,
        after={"username": username, "role": role, "telegram_user_id": telegram_user_id},
    )
    return user


def get_user_by_username(session: Session, username: str) -> User:
    user = session.scalar(select(User).where(User.username == username))
    if user is None:
        raise NotFoundError(f"user {username!r} not found")
    return user


def create_api_key(
    session: Session,
    user: User,
    *,
    name: str = "default",
    expires_in_days: int | None = None,
    now: datetime | None = None,
) -> tuple[str, ApiKey]:
    """Create a key. The plaintext is returned once and never stored."""
    now = now or utcnow()
    plaintext, prefix, digest = generate_api_key()
    key = ApiKey(
        user_id=user.id,
        name=name,
        key_prefix=prefix,
        key_hash=digest,
        scopes=[],
        expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
    )
    session.add(key)
    session.flush()
    audit.record(
        session,
        Actor.system("cli"),
        action="api_key.create",
        entity_type="api_key",
        entity_id=key.id,
        after={"user_id": user.id, "name": name, "prefix": prefix},
    )
    return plaintext, key


def revoke_api_key(session: Session, prefix: str, *, now: datetime | None = None) -> ApiKey:
    key = session.scalar(
        select(ApiKey).where(ApiKey.key_prefix == prefix, ApiKey.revoked_at.is_(None))
    )
    if key is None:
        raise NotFoundError("no active API key with that prefix")
    key.revoked_at = now or utcnow()
    audit.record(
        session,
        Actor.system("cli"),
        action="api_key.revoke",
        entity_type="api_key",
        entity_id=key.id,
    )
    return key


def authenticate_api_key(
    session: Session, token: str, *, now: datetime | None = None
) -> tuple[User, ApiKey] | None:
    """Return the owner of a valid key, or None. Constant work regardless of key validity."""
    now = now or utcnow()
    digest = hash_api_key(token)
    key = session.scalar(select(ApiKey).where(ApiKey.key_hash == digest))
    if key is None or key.revoked_at is not None:
        return None
    if key.expires_at is not None and key.expires_at <= now:
        return None
    user = session.get(User, key.user_id)
    if user is None or not user.is_active:
        return None
    if key.last_used_at is None or now - key.last_used_at > LAST_USED_WRITE_INTERVAL:
        key.last_used_at = now
    return user, key


def user_for_telegram(session: Session, telegram_user_id: int) -> User | None:
    return session.scalar(
        select(User).where(User.telegram_user_id == telegram_user_id, User.is_active.is_(True))
    )


def ensure_telegram_user(session: Session, telegram_user_id: int, username: str | None) -> User:
    """Get or create the user for an *allowlisted* Telegram account (caller checks the list)."""
    user = session.scalar(select(User).where(User.telegram_user_id == telegram_user_id))
    if user is not None:
        if not user.is_active:
            raise PermissionDeniedError("this Telegram account's user is disabled")
        return user
    base = (username or f"tg{telegram_user_id}")[:48]
    candidate = base
    suffix = 1
    while session.scalar(select(User.id).where(User.username == candidate)) is not None:
        suffix += 1
        candidate = f"{base}-{suffix}"
    user = User(username=candidate, telegram_user_id=telegram_user_id, role="owner")
    session.add(user)
    session.flush()
    return user
