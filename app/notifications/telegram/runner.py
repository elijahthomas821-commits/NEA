"""Running the bot: long polling (default) or webhook registration.

Polling keeps its offset in ``bot_state``; the offset only moves past an update once it has
been handled, so a crash re-delivers at most the update in progress (and ``claim_update``
stops it being handled twice). A database outage pauses the loop instead of skipping updates;
an update that keeps failing for another reason is skipped after a few attempts so it cannot
block the bot forever.
"""

from __future__ import annotations

import signal
import threading
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from app.config.settings import Settings, get_settings
from app.core.enums import AlertMode
from app.core.logging import configure_logging, get_logger
from app.core.redaction import safe_error_summary
from app.core.time import utcnow
from app.database.session import Database, get_database
from app.notifications.telegram import state
from app.notifications.telegram.client import (
    TelegramClient,
    TelegramConflictError,
    TelegramError,
    TelegramRetryAfterError,
    TelegramUnauthorizedError,
    TelegramUnavailableError,
)
from app.notifications.telegram.factory import build_telegram_client
from app.notifications.telegram.handlers import COMMANDS, BotHandler, Outbox
from app.notifications.telegram.types import ALLOWED_UPDATES, TgUpdate
from app.workers.dispatch import CeleryDispatcher, TaskDispatcher

log = get_logger(__name__)

MAX_ATTEMPTS = 3
MAX_INLINE_RETRY_AFTER = 30


class TelegramBot:
    """Handles one update at a time: de-duplicate → handle (one transaction) → side effects."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        client: TelegramClient,
        dispatcher: TaskDispatcher,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.database = database
        self.client = client
        self.dispatcher = dispatcher
        self.clock = clock
        self.sleep = sleep
        self.handler = BotHandler(settings, client, clock=clock)

    def process_update(self, payload: dict[str, Any]) -> None:
        try:
            update = TgUpdate.model_validate(payload)
        except ValidationError:
            log.warning("telegram_update_invalid")
            return
        outbox = Outbox()
        with self.database.session_scope() as session:
            if not state.claim_update(session, update.update_id, now=self.clock()):
                log.info("telegram_update_duplicate", update_id=update.update_id)
                return
            self.handler.handle(session, update, outbox)
        self.deliver(outbox)

    def deliver(self, outbox: Outbox) -> None:
        """Perform the side effects of a handled update (after its transaction committed)."""
        client = self.client
        for answer in outbox.answers:
            self._safe(
                client.answer_callback_query,
                answer.callback_id,
                answer.text,
                show_alert=answer.show_alert,
            )
        for edit in outbox.edits:
            self._safe(
                client.edit_message_reply_markup, edit.chat_id, edit.message_id, edit.keyboard
            )
        for message in outbox.messages:
            self._safe(
                client.send_message, message.chat_id, message.text, reply_markup=message.keyboard
            )
        for request in outbox.evaluations:
            try:
                self.dispatcher.evaluate_listing(
                    request.listing_id, trigger=request.trigger, alert=AlertMode.ALWAYS
                )
            except Exception as exc:  # the queue is down: the listing is saved, say so
                log.error(
                    "evaluation_dispatch_failed",
                    listing_id=request.listing_id,
                    error=safe_error_summary(exc),
                )
                chat_id = self.settings.alert_chat_id
                if chat_id is not None:
                    self._safe(
                        client.send_message,
                        chat_id,
                        f"Saved #{request.listing_id}, but I couldn't queue the evaluation. "
                        f"Try /check {request.listing_id} in a minute.",
                    )

    def _safe(self, call: Callable[..., object], *args: Any, **kwargs: Any) -> None:
        """One Bot API call; a short flood wait or a network blip is retried once."""
        method = getattr(call, "__name__", "call")
        for attempt in (1, 2):
            try:
                call(*args, **kwargs)
                return
            except TelegramRetryAfterError as exc:
                if attempt == 1 and exc.retry_after <= MAX_INLINE_RETRY_AFTER:
                    self.sleep(exc.retry_after)
                    continue
                log.warning("telegram_call_dropped", method=method, error=exc.description)
            except TelegramUnavailableError as exc:
                if attempt == 1:
                    self.sleep(1)
                    continue
                log.warning("telegram_call_dropped", method=method, error=exc.description)
            except TelegramError as exc:
                log.warning("telegram_call_failed", method=method, error=exc.description)
            return

    def apologise(self, payload: dict[str, Any]) -> None:
        """Best effort, after an update could not be handled at all."""
        try:
            update = TgUpdate.model_validate(payload)
        except ValidationError:
            return
        sender = update.sender
        if sender is None or sender.id not in self.settings.telegram_allowed_user_ids:
            return
        chat_id = (
            update.message.chat.id
            if update.message is not None
            else (
                update.callback_query.message.chat.id
                if update.callback_query is not None and update.callback_query.message
                else sender.id
            )
        )
        self._safe(
            self.client.send_message,
            chat_id,
            "Sorry — something went wrong handling that. Please try again.",
        )


class Poller:
    def __init__(
        self,
        bot: TelegramBot,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.bot = bot
        self.sleep = sleep
        self.stop_event = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()

    def prepare(self) -> None:
        """Polling and webhooks are mutually exclusive: make sure no webhook is set."""
        self.bot.client.delete_webhook()
        try:
            self.bot.client.set_my_commands(COMMANDS)
        except TelegramError as exc:
            log.warning("telegram_set_commands_failed", error=exc.description)

    def run(self) -> None:
        self.prepare()
        log.info("telegram_polling_started")
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                self.poll_once()
                backoff = 1.0
            except TelegramUnauthorizedError:
                log.error("telegram_token_rejected")
                raise
            except TelegramRetryAfterError as exc:
                self.sleep(exc.retry_after)
            except (TelegramUnavailableError, TelegramConflictError, OperationalError) as exc:
                log.warning("telegram_poll_backoff", error=safe_error_summary(exc), wait=backoff)
                self.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
        log.info("telegram_polling_stopped")

    def poll_once(self) -> int:
        bot = self.bot
        with bot.database.session_scope() as session:
            offset = state.get_poll_offset(session)
        updates = bot.client.get_updates(
            offset=offset,
            timeout=bot.settings.telegram_poll_timeout_seconds,
            allowed_updates=ALLOWED_UPDATES,
        )
        handled = 0
        for payload in updates:
            update_id = payload.get("update_id") if isinstance(payload, dict) else None
            if not isinstance(update_id, int):
                continue
            if self.stop_event.is_set():
                break  # not acknowledged: Telegram re-delivers it next time
            self._process(payload)
            with bot.database.session_scope() as session:
                state.set_poll_offset(session, update_id + 1, now=bot.clock())
            handled += 1
        return handled

    def _process(self, payload: dict[str, Any]) -> None:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                self.bot.process_update(payload)
                return
            except OperationalError:
                raise  # database unavailable: retry the whole batch later, skip nothing
            except Exception as exc:
                log.error(
                    "telegram_update_failed",
                    update_id=payload.get("update_id"),
                    attempt=attempt,
                    error=safe_error_summary(exc),
                )
                if attempt < MAX_ATTEMPTS:
                    self.sleep(attempt)
        self.bot.apologise(payload)


def register_webhook(client: TelegramClient, settings: Settings) -> None:
    if not settings.telegram_webhook_url or settings.telegram_webhook_secret is None:
        raise ValueError("webhook mode needs TELEGRAM_WEBHOOK_URL and TELEGRAM_WEBHOOK_SECRET")
    client.set_webhook(
        settings.telegram_webhook_url,
        secret_token=settings.telegram_webhook_secret.get_secret_value(),
        allowed_updates=ALLOWED_UPDATES,
        max_connections=1,
    )
    client.set_my_commands(COMMANDS)


def build_bot(
    settings: Settings,
    *,
    database: Database | None = None,
    dispatcher: TaskDispatcher | None = None,
    client: TelegramClient | None = None,
) -> TelegramBot | None:
    client = client or build_telegram_client(settings)
    if client is None:
        return None
    return TelegramBot(
        settings=settings,
        database=database or get_database(),
        client=client,
        dispatcher=dispatcher or CeleryDispatcher(),
    )


def run_bot(settings: Settings | None = None) -> int:
    """``resale bot``: poll for updates, or (webhook mode) register the webhook and exit."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    bot = build_bot(settings)
    if bot is None:
        log.error("telegram_not_configured", hint="set TELEGRAM_BOT_TOKEN")
        return 2
    if not settings.telegram_allowed_user_ids:
        log.warning(
            "telegram_allowlist_empty",
            hint="send /start to the bot to see your user ID, then set TELEGRAM_ALLOWED_USER_IDS",
        )
    try:
        if settings.telegram_mode == "webhook":
            register_webhook(bot.client, settings)
            log.info("telegram_webhook_registered")
            return 0
        poller = Poller(bot)

        def _stop(_signum: int, _frame: object) -> None:
            poller.stop()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        poller.run()
        return 0
    except TelegramUnauthorizedError:
        return 3
    finally:
        bot.client.close()
