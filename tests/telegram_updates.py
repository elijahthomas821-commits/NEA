"""Builders for Telegram updates, and a fake file API for photo downloads."""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.notifications.telegram.client import FileTooLargeError, TelegramUnavailableError
from app.notifications.telegram.handlers import BotHandler, Outbox
from app.notifications.telegram.types import TgUpdate

OPERATOR = 111
BOT_NOW = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)
_ids = itertools.count(10_000)


def _sender(user_id: int) -> dict[str, Any]:
    return {"id": user_id, "is_bot": False, "username": f"user{user_id}", "first_name": "Op"}


def message(
    text: str | None = None,
    *,
    user_id: int = OPERATOR,
    chat_id: int | None = None,
    chat_type: str = "private",
    caption: str | None = None,
    photo: str | None = None,
    photo_size: int = 50_000,
    document: dict[str, Any] | None = None,
    media_group_id: str | None = None,
    update_id: int | None = None,
) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "message_id": next(_ids),
        "date": 1_790_000_000,
        "chat": {"id": chat_id if chat_id is not None else user_id, "type": chat_type},
        "from": _sender(user_id),
    }
    if text is not None:
        msg["text"] = text
    if caption is not None:
        msg["caption"] = caption
    if photo is not None:
        msg["photo"] = [
            {"file_id": f"{photo}-small", "file_unique_id": "s", "width": 90, "height": 90,
             "file_size": 1_000},
            {"file_id": photo, "file_unique_id": f"u-{photo}", "width": 1280, "height": 960,
             "file_size": photo_size},
        ]  # fmt: skip
    if document is not None:
        msg["document"] = document
    if media_group_id is not None:
        msg["media_group_id"] = media_group_id
    return {"update_id": update_id if update_id is not None else next(_ids), "message": msg}


def callback(
    data: str,
    *,
    user_id: int = OPERATOR,
    chat_id: int | None = None,
    message_id: int = 500,
    update_id: int | None = None,
) -> dict[str, Any]:
    return {
        "update_id": update_id if update_id is not None else next(_ids),
        "callback_query": {
            "id": f"cb{next(_ids)}",
            "from": _sender(user_id),
            "data": data,
            "message": {
                "message_id": message_id,
                "date": 1_790_000_000,
                "chat": {"id": chat_id if chat_id is not None else user_id, "type": "private"},
            },
        },
    }


class FakeFiles:
    """Stands in for the Bot API file endpoints (getFile + download)."""

    def __init__(self, files: dict[str, bytes] | None = None, *, fail: bool = False) -> None:
        self.files = files or {}
        self.fail = fail
        self.downloads: list[str] = []

    def get_file(self, file_id: str) -> dict[str, Any]:
        if self.fail:
            raise TelegramUnavailableError("getFile: timed out")
        return {"file_id": file_id, "file_path": f"photos/{file_id}.jpg"}

    def download_file(self, file_path: str, *, max_bytes: int) -> bytes:
        file_id = file_path.removeprefix("photos/").removesuffix(".jpg")
        data = self.files[file_id]
        if len(data) > max_bytes:
            raise FileTooLargeError(max_bytes)
        self.downloads.append(file_id)
        return data


@dataclass
class Harness:
    """Runs updates through the handler the way the bot does: one transaction each."""

    handler: BotHandler
    test_db: Any
    db_session: Session

    def send(self, update: dict[str, Any]) -> Outbox:
        outbox = Outbox()
        with self.test_db.session_scope() as session:
            self.handler.handle(session, TgUpdate.model_validate(update), outbox)
        self.db_session.expire_all()
        return outbox


def last(outbox: Outbox) -> str:
    assert outbox.messages, "no reply"
    return outbox.messages[-1].text
