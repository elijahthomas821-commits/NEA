"""The subset of Telegram's Update object the bot reads. Unknown fields are ignored."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _TG(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, populate_by_name=True)


class TgUser(_TG):
    id: int
    is_bot: bool = False
    username: str | None = None
    first_name: str | None = None


class TgChat(_TG):
    id: int
    type: str = "private"


class TgPhotoSize(_TG):
    file_id: str
    file_unique_id: str | None = None
    width: int = 0
    height: int = 0
    file_size: int | None = None


class TgDocument(_TG):
    file_id: str
    file_unique_id: str | None = None
    file_name: str | None = None
    mime_type: str | None = None
    file_size: int | None = None


class TgMessage(_TG):
    message_id: int
    chat: TgChat
    from_user: TgUser | None = Field(default=None, alias="from")
    date: int = 0
    text: str | None = None
    caption: str | None = None
    photo: list[TgPhotoSize] = Field(default_factory=list)
    document: TgDocument | None = None
    media_group_id: str | None = None

    @property
    def content(self) -> str:
        return (self.text or self.caption or "").strip()

    @property
    def has_image(self) -> bool:
        return bool(self.photo) or (
            self.document is not None
            and (self.document.mime_type or "").lower().startswith("image/")
        )


class TgCallbackQuery(_TG):
    id: str
    from_user: TgUser = Field(alias="from")
    message: TgMessage | None = None
    data: str | None = None


class TgUpdate(_TG):
    update_id: int
    message: TgMessage | None = None
    callback_query: TgCallbackQuery | None = None

    @property
    def sender(self) -> TgUser | None:
        if self.callback_query is not None:
            return self.callback_query.from_user
        if self.message is not None:
            return self.message.from_user
        return None


ALLOWED_UPDATES = ["message", "callback_query"]
