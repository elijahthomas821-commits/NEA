"""Bot API client: error mapping, payloads, downloads, and never leaking the token."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.notifications.telegram.client import (
    TEXT_LIMIT,
    FileTooLargeError,
    TelegramClient,
    TelegramConflictError,
    TelegramError,
    TelegramRejectedError,
    TelegramRetryAfterError,
    TelegramUnauthorizedError,
    TelegramUnavailableError,
)

TOKEN = "123456789:AAH-secret-token-value-abcdefghijklmnopq"
API = "https://api.telegram.org"
BOT = f"{API}/bot{TOKEN}"


@pytest.fixture
def client():
    with TelegramClient(TOKEN) as c:
        yield c


def ok(result):
    return httpx.Response(200, json={"ok": True, "result": result})


def error(code, description, **parameters):
    body = {"ok": False, "error_code": code, "description": description}
    if parameters:
        body["parameters"] = parameters
    return httpx.Response(code, json=body)


def assert_no_token(exc: BaseException) -> None:
    assert TOKEN not in str(exc)
    assert TOKEN not in repr(exc)
    assert exc.__cause__ is None  # the httpx exception (which holds the URL) is not chained


@respx.mock
def test_send_message_payload(client):
    route = respx.post(f"{BOT}/sendMessage").mock(return_value=ok({"message_id": 9}))
    result = client.send_message(
        42, "x" * (TEXT_LIMIT + 50), reply_markup={"inline_keyboard": []}, reply_to_message_id=7
    )
    assert result == {"message_id": 9}
    body = json.loads(route.calls.last.request.content)
    assert body["chat_id"] == 42
    assert body["parse_mode"] == "HTML"
    assert body["link_preview_options"] == {"is_disabled": True}
    assert len(body["text"]) == TEXT_LIMIT
    assert body["reply_parameters"] == {"message_id": 7, "allow_sending_without_reply": True}


@respx.mock
def test_none_parameters_are_dropped(client):
    route = respx.post(f"{BOT}/sendMessage").mock(return_value=ok({"message_id": 1}))
    client.send_message(1, "hi")
    body = json.loads(route.calls.last.request.content)
    assert "reply_markup" not in body
    assert "reply_parameters" not in body


@pytest.mark.parametrize(
    ("response", "exc_type"),
    [
        (error(429, "Too Many Requests: retry after 7", retry_after=7), TelegramRetryAfterError),
        (error(500, "Internal Server Error"), TelegramUnavailableError),
        (error(502, "Bad Gateway"), TelegramUnavailableError),
        (error(401, "Unauthorized"), TelegramUnauthorizedError),
        (error(409, "Conflict: terminated by other getUpdates request"), TelegramConflictError),
        (error(400, "Bad Request: chat not found"), TelegramRejectedError),
        (error(403, "Forbidden: bot was blocked by the user"), TelegramRejectedError),
        (httpx.Response(502, text="<html>bad gateway</html>"), TelegramUnavailableError),
        (httpx.Response(404, text="not json"), TelegramRejectedError),
    ],
)
@respx.mock
def test_error_mapping(client, response, exc_type):
    respx.post(f"{BOT}/sendMessage").mock(return_value=response)
    with pytest.raises(exc_type) as info:
        client.send_message(1, "hi")
    assert_no_token(info.value)
    assert info.value.description.startswith("sendMessage")


@respx.mock
def test_retry_after_value(client):
    respx.post(f"{BOT}/getMe").mock(return_value=error(429, "slow down", retry_after=7))
    with pytest.raises(TelegramRetryAfterError) as info:
        client.get_me()
    assert info.value.retry_after == 7
    assert info.value.retryable


def test_retryable_flags():
    assert TelegramUnavailableError("x").retryable
    assert TelegramConflictError("x").retryable
    assert not TelegramRejectedError("x").retryable
    assert not TelegramUnauthorizedError("x").retryable


@pytest.mark.parametrize(
    "side_effect",
    [httpx.ConnectError("boom"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("x")],
)
@respx.mock
def test_network_errors_do_not_leak_the_url(client, side_effect):
    respx.post(f"{BOT}/sendMessage").mock(side_effect=side_effect)
    with pytest.raises(TelegramUnavailableError) as info:
        client.send_message(1, "hi")
    assert_no_token(info.value)


@respx.mock
def test_edit_markup_ignores_not_modified(client):
    respx.post(f"{BOT}/editMessageReplyMarkup").mock(
        return_value=error(400, "Bad Request: message is not modified")
    )
    client.edit_message_reply_markup(1, 2, None)  # no exception

    respx.post(f"{BOT}/editMessageReplyMarkup").mock(
        return_value=error(400, "Bad Request: message to edit not found")
    )
    with pytest.raises(TelegramRejectedError):
        client.edit_message_reply_markup(1, 2, None)


@respx.mock
def test_get_updates_uses_a_longer_http_timeout(client):
    route = respx.post(f"{BOT}/getUpdates").mock(return_value=ok([{"update_id": 5}]))
    assert client.get_updates(offset=5, timeout=30, allowed_updates=["message"]) == [
        {"update_id": 5}
    ]
    request = route.calls.last.request
    assert json.loads(request.content) == {
        "offset": 5,
        "timeout": 30,
        "allowed_updates": ["message"],
    }
    assert request.extensions["timeout"]["read"] == 40


@respx.mock
def test_webhook_and_commands(client):
    hook = respx.post(f"{BOT}/setWebhook").mock(return_value=ok(True))
    commands = respx.post(f"{BOT}/setMyCommands").mock(return_value=ok(True))
    delete = respx.post(f"{BOT}/deleteWebhook").mock(return_value=ok(True))
    answer = respx.post(f"{BOT}/answerCallbackQuery").mock(return_value=ok(True))
    client.set_webhook(
        "https://example.test/telegram/webhook", secret_token="s" * 20, allowed_updates=["message"]
    )
    client.set_my_commands([("help", "How to use this bot")])
    client.delete_webhook()
    client.answer_callback_query("cb1", "Done")
    assert json.loads(hook.calls.last.request.content)["max_connections"] == 1
    assert json.loads(commands.calls.last.request.content) == {
        "commands": [{"command": "help", "description": "How to use this bot"}]
    }
    assert delete.called
    assert json.loads(answer.calls.last.request.content) == {
        "callback_query_id": "cb1",
        "text": "Done",
    }


class TestDownload:
    @respx.mock
    def test_download(self, client):
        respx.post(f"{BOT}/getFile").mock(
            return_value=ok({"file_id": "f", "file_path": "photos/file_1.jpg", "file_size": 3})
        )
        respx.get(f"{API}/file/bot{TOKEN}/photos/file_1.jpg").mock(
            return_value=httpx.Response(200, content=b"abc")
        )
        info = client.get_file("f")
        assert client.download_file(info["file_path"], max_bytes=10) == b"abc"

    @respx.mock
    def test_declared_size_too_large(self, client):
        respx.get(f"{API}/file/bot{TOKEN}/photos/big.jpg").mock(
            return_value=httpx.Response(200, content=b"x" * 20)
        )
        with pytest.raises(FileTooLargeError):
            client.download_file("photos/big.jpg", max_bytes=10)

    @respx.mock
    def test_streamed_size_too_large(self, client):
        def chunks():
            yield b"x" * 8
            yield b"x" * 8

        respx.get(f"{API}/file/bot{TOKEN}/photos/stream.jpg").mock(
            return_value=httpx.Response(200, content=chunks())
        )
        with pytest.raises(FileTooLargeError):
            client.download_file("photos/stream.jpg", max_bytes=10)

    @pytest.mark.parametrize("path", ["../etc/passwd", "photos/../../x", "a b.jpg", "", "a.jpg\n"])
    def test_rejects_odd_paths(self, client, path):
        with pytest.raises(TelegramRejectedError):
            client.download_file(path, max_bytes=10)

    @respx.mock
    def test_http_errors(self, client):
        respx.get(f"{API}/file/bot{TOKEN}/photos/gone.jpg").mock(return_value=httpx.Response(404))
        respx.get(f"{API}/file/bot{TOKEN}/photos/down.jpg").mock(return_value=httpx.Response(503))
        respx.get(f"{API}/file/bot{TOKEN}/photos/net.jpg").mock(side_effect=httpx.ConnectError("x"))
        with pytest.raises(TelegramRejectedError):
            client.download_file("photos/gone.jpg", max_bytes=10)
        with pytest.raises(TelegramUnavailableError):
            client.download_file("photos/down.jpg", max_bytes=10)
        with pytest.raises(TelegramUnavailableError) as info:
            client.download_file("photos/net.jpg", max_bytes=10)
        assert_no_token(info.value)


def test_requires_token():
    with pytest.raises(ValueError, match="token"):
        TelegramClient("")


def test_errors_are_telegram_errors():
    for exc_type in (
        TelegramRetryAfterError,
        TelegramUnavailableError,
        TelegramConflictError,
        TelegramUnauthorizedError,
        TelegramRejectedError,
    ):
        assert issubclass(exc_type, TelegramError)
