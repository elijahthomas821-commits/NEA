"""The operator's chat interface.

Only allowlisted Telegram accounts are served. Each update is handled inside one database
transaction; everything with an outside effect (messages, button updates, queued evaluations)
is collected in an :class:`Outbox` and performed only after the transaction commits, so the
worker always sees the data and nothing is announced that was rolled back.

What you can do in the chat:

* paste a Vinted link (plus the price, if you know it) → the listing is saved and evaluated;
* send photos (labels, badges, tags) → attached to the listing you are working on;
* ``/add`` → step-by-step entry; ``/check``, ``/price``, ``/sold``, ``/gone``, ``/show``,
  ``/recent``; ``/comp`` records a sold item you found (market data);
* BUY / PASS / REVIEW on alerts. BUY only records your intent; after you have bought the item
  yourself, the bot asks what you paid and records the purchase. It never buys anything.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.normalisation.condition import match_condition_label
from app.collectors.base import RawSale
from app.collectors.vinted.mapping import find_item_url, parse_item_url
from app.config.settings import Settings
from app.core.enums import (
    Condition,
    ListingStatus,
    SaleSource,
    UserDecision,
)
from app.core.errors import (
    AppError,
    ExternalServiceError,
    InvalidStateError,
    NotFoundError,
    PermissionDeniedError,
    ValidationFailedError,
)
from app.core.logging import get_logger
from app.core.money import format_money
from app.core.time import utcnow
from app.models import Alert, Listing, ListingEvaluation, User
from app.notifications.telegram import state
from app.notifications.telegram.client import (
    FileTooLargeError,
    TelegramClient,
    TelegramError,
)
from app.notifications.telegram.formatter import (
    Callback,
    clip,
    condition_keyboard,
    confirm_keyboard,
    decision_keyboard,
    esc,
    evaluate_keyboard,
    format_alert,
    format_decision_note,
    parse_callback,
    skip_keyboard,
)
from app.notifications.telegram.inventory_commands import InventoryCommands
from app.notifications.telegram.parsing import (
    COMP_EXAMPLE,
    COMP_FORMAT,
    parse_amount,
    parse_amounts,
    parse_command,
    parse_comp,
    parse_listing_ref,
)
from app.notifications.telegram.types import TgCallbackQuery, TgMessage, TgUpdate, TgUser
from app.services.alerts import (
    build_alert_view,
    latest_alert_for_listing,
    latest_evaluation,
    record_decision,
)
from app.services.audit import Actor
from app.services.catalogue import load_catalogue
from app.services.config_service import ConfigService
from app.services.images import add_listing_image
from app.services.ingestion import (
    IngestResult,
    ingest_listing,
    set_listing_details,
    update_listing,
)
from app.services.market_data import record_sale, record_sold_observation
from app.services.purchases import (
    PurchaseCosts,
    estimate_costs,
    existing_purchase_for_listing,
    record_purchase,
    with_total_paid,
)
from app.services.submissions import raw_listing_from_text
from app.services.users import ensure_telegram_user

log = get_logger(__name__)

HELP = """<b>Resale assistant</b> — I estimate resale price, profit and risk for listings you \
send me. I never buy anything.

<b>Check a listing:</b> paste the Vinted link, with the price if you know it:
<code>https://www.vinted.co.uk/items/123-stone-island-crewneck £45</code>
Photos of labels, badges and tags improve the authenticity check: send them after the link, \
or with the link as the photo caption.

/add – step-by-step entry (link, price, brand, size, condition, photos)
/check 12 – re-evaluate listing #12
/price 12 £40 – the asking price changed
/sold 12 – it sold to someone else (its last price is kept as market data)
/gone 12 – the listing was removed
/show 12 – the latest result for #12
/recent – your latest listings
/comp – record a sold item you found (market data for pricing)
/cancel – stop the current question

<b>Your stock</b> (item numbers, e.g. 7):
/stock – what you hold · /item 7 – one item · /stats – last 30 days
/received 7 · /listed 7 £99 · /sale 7 £95 · /shipped 7 · /done 7 · /writeoff 7

Alerts have BUY / PASS / REVIEW buttons. BUY only records your decision: buy the item \
yourself, then tell me what you paid.
<i>Estimates only — not guaranteed outcomes.</i>"""

COMMANDS = [
    ("add", "Step-by-step listing entry"),
    ("check", "Re-evaluate a listing: /check 12"),
    ("price", "The price changed: /price 12 £40"),
    ("sold", "It sold to someone else: /sold 12"),
    ("gone", "The listing was removed: /gone 12"),
    ("show", "Latest result: /show 12"),
    ("recent", "Your latest listings"),
    ("comp", "Record a sold item (market data)"),
    ("stock", "What you hold"),
    ("item", "One stock item: /item 7"),
    ("received", "It arrived: /received 7"),
    ("listed", "You listed it: /listed 7 £99"),
    ("sale", "You sold it: /sale 7 £95"),
    ("shipped", "You posted it: /shipped 7"),
    ("done", "Sale completed: /done 7"),
    ("writeoff", "Lost or unsellable: /writeoff 7"),
    ("stats", "The last 30 days"),
    ("cancel", "Stop the current question"),
    ("help", "How to use this bot"),
]

LIVE = (ListingStatus.ACTIVE.value, ListingStatus.RESERVED.value)
DECISION_WORDS = {UserDecision.BUY: "BUY", UserDecision.PASS: "PASS", UserDecision.REVIEW: "REVIEW"}


# --------------------------------------------------------------------------- outbox


@dataclass(frozen=True)
class OutMessage:
    chat_id: int
    text: str
    keyboard: dict[str, Any] | None = None


@dataclass(frozen=True)
class MarkupEdit:
    chat_id: int
    message_id: int
    keyboard: dict[str, Any] | None


@dataclass(frozen=True)
class CallbackAnswer:
    callback_id: str
    text: str | None = None
    show_alert: bool = False


@dataclass(frozen=True)
class EvaluationRequest:
    listing_id: int
    trigger: str


@dataclass
class Outbox:
    messages: list[OutMessage] = field(default_factory=list)
    edits: list[MarkupEdit] = field(default_factory=list)
    answers: list[CallbackAnswer] = field(default_factory=list)
    evaluations: list[EvaluationRequest] = field(default_factory=list)

    def send(self, chat_id: int, text: str, keyboard: dict[str, Any] | None = None) -> None:
        self.messages.append(OutMessage(chat_id, text, keyboard))

    def edit_markup(self, chat_id: int, message_id: int, keyboard: dict[str, Any] | None) -> None:
        self.edits.append(MarkupEdit(chat_id, message_id, keyboard))

    def answer(
        self, callback_id: str, text: str | None = None, *, show_alert: bool = False
    ) -> None:
        self.answers.append(CallbackAnswer(callback_id, text, show_alert))

    def evaluate(self, listing_id: int, trigger: str) -> None:
        if all(r.listing_id != listing_id for r in self.evaluations):
            self.evaluations.append(EvaluationRequest(listing_id, trigger))

    def clear(self) -> None:
        self.messages.clear()
        self.edits.clear()
        self.answers.clear()
        self.evaluations.clear()


@dataclass
class Turn:
    """One update being handled."""

    session: Session
    user: User
    actor: Actor
    sender_id: int
    chat_id: int
    now: datetime
    outbox: Outbox

    def reply(self, text: str, keyboard: dict[str, Any] | None = None) -> None:
        self.outbox.send(self.chat_id, text, keyboard)

    # conversation state ---------------------------------------------------------------

    @property
    def conversation_key(self) -> str:
        return state.conversation_key(self.chat_id, self.sender_id)

    def conversation(self) -> dict[str, Any] | None:
        return state.get_value(self.session, self.conversation_key, now=self.now)

    def set_conversation(self, value: dict[str, Any]) -> None:
        state.set_value(
            self.session, self.conversation_key, value, now=self.now, ttl=state.CONVERSATION_TTL
        )

    def end_conversation(self) -> None:
        state.delete_value(self.session, self.conversation_key)

    def focus(self, listing_id: int) -> None:
        state.set_value(
            self.session,
            state.focus_key(self.sender_id),
            {"listing_id": listing_id},
            now=self.now,
            ttl=state.FOCUS_TTL,
        )

    def focused_listing_id(self) -> int | None:
        value = state.get_value(self.session, state.focus_key(self.sender_id), now=self.now)
        listing_id = (value or {}).get("listing_id")
        return listing_id if isinstance(listing_id, int) else None


def _error_text(exc: AppError) -> str:
    errors = exc.details.get("errors") if isinstance(exc.details, dict) else None
    if errors and isinstance(errors, list):
        parts = [f"{e.get('loc')}: {e.get('msg')}" for e in errors[:3] if isinstance(e, dict)]
        return f"{exc.message} ({'; '.join(parts)})"
    return exc.message


def _listing_label(listing: Listing) -> str:
    price = ""
    if listing.price is not None and listing.currency is not None:
        price = f" · {format_money(listing.price, listing.currency)}"
    return f"#{listing.id} {esc(clip(listing.title, 60))}{price}"


def _money(value: Decimal, currency: str) -> str:
    return format_money(value, currency)


# --------------------------------------------------------------------------- handler


class BotHandler:
    def __init__(
        self,
        settings: Settings,
        client: TelegramClient | None,
        *,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.settings = settings
        self.client = client
        self.clock = clock
        self.inventory = InventoryCommands(self)

    # ------------------------------------------------------------------ entry point

    def handle(self, session: Session, update: TgUpdate, outbox: Outbox) -> None:
        sender = update.sender
        if sender is None or sender.is_bot:
            return
        chat_id = self._chat_id(update, sender)
        if sender.id not in self.settings.telegram_allowed_user_ids:
            self._unauthorised(update, sender, chat_id, outbox)
            return
        now = self.clock()
        try:
            user = ensure_telegram_user(session, sender.id, sender.username)
        except PermissionDeniedError:
            self._unauthorised(update, sender, chat_id, outbox)
            return
        user.last_seen_at = now
        turn = Turn(
            session=session,
            user=user,
            actor=Actor(user_id=user.id, label=f"telegram:{sender.id}"),
            sender_id=sender.id,
            chat_id=chat_id,
            now=now,
            outbox=outbox,
        )
        savepoint = session.begin_nested()
        try:
            if update.callback_query is not None:
                self._on_callback(turn, update.callback_query)
            elif update.message is not None:
                self._on_message(turn, update.message)
            savepoint.commit()
        except AppError as exc:
            # Nothing from this update is kept or announced except the explanation.
            savepoint.rollback()
            outbox.clear()
            if update.callback_query is not None:
                outbox.answer(update.callback_query.id, clip(_error_text(exc), 190))
            turn.reply(f"⚠️ {esc(_error_text(exc))}")

    @staticmethod
    def _chat_id(update: TgUpdate, sender: TgUser) -> int:
        if update.callback_query is not None and update.callback_query.message is not None:
            return update.callback_query.message.chat.id
        if update.message is not None:
            return update.message.chat.id
        return sender.id

    @staticmethod
    def _unauthorised(update: TgUpdate, sender: TgUser, chat_id: int, outbox: Outbox) -> None:
        log.warning("telegram_unauthorised", telegram_user_id=sender.id)
        if update.callback_query is not None:
            outbox.answer(update.callback_query.id, "Not authorised.")
            return
        message = update.message
        if message is not None and message.chat.type == "private":
            parsed = parse_command(message.content)
            if parsed is not None and parsed[0] == "start":
                outbox.send(
                    chat_id,
                    "This is a private bot. Your Telegram user ID is "
                    f"<code>{sender.id}</code> — if this is your bot, add it to "
                    "TELEGRAM_ALLOWED_USER_IDS and restart it.",
                )

    # ------------------------------------------------------------------ messages

    def _on_message(self, turn: Turn, message: TgMessage) -> None:
        if message.has_image:
            self._on_photo(turn, message)
            return
        text = message.content
        if not text:
            turn.reply("I can read text and photos. /help shows what I can do.")
            return
        parsed = parse_command(text)
        if parsed is not None:
            self._on_command(turn, *parsed)
            return
        if find_item_url(text) is not None:
            conversation = turn.conversation()
            if (
                conversation
                and conversation.get("flow") == "add"
                and not conversation.get("listing_id")
            ):
                self._continue(turn, conversation, text=text)
                return
            turn.end_conversation()
            self._quick_add(turn, text)
            return
        conversation = turn.conversation()
        if conversation is not None:
            self._continue(turn, conversation, text=text)
            return
        if parse_amount(text) is not None and any(ch.isalpha() for ch in text):
            self._quick_add(turn, text)  # "Stone Island crewneck L £45" without a link
            return
        turn.reply(
            "Send me a Vinted link (with the price if you know it), or /help for everything else."
        )

    def _on_command(self, turn: Turn, command: str, args: str) -> None:
        handlers: dict[str, Callable[[Turn, str], None]] = {
            "start": self._cmd_help,
            "help": self._cmd_help,
            "add": self._cmd_add,
            "cancel": self._cmd_cancel,
            "check": self._cmd_check,
            "price": self._cmd_price,
            "sold": self._cmd_sold,
            "gone": self._cmd_gone,
            "show": self._cmd_show,
            "recent": self._cmd_recent,
            "comp": self._cmd_comp,
            **self.inventory.commands,
        }
        handler = handlers.get(command)
        if handler is None:
            turn.reply(f"Unknown command /{esc(command)}. /help lists what I can do.")
            return
        handler(turn, args)

    # ------------------------------------------------------------------ commands

    def _cmd_help(self, turn: Turn, _args: str) -> None:
        turn.reply(HELP)

    def _cmd_cancel(self, turn: Turn, _args: str) -> None:
        if turn.conversation() is None:
            turn.reply("Nothing to cancel.")
            return
        turn.end_conversation()
        turn.reply("Cancelled.")

    def _cmd_add(self, turn: Turn, args: str) -> None:
        turn.set_conversation({"flow": "add", "step": "link"})
        if args:
            self._continue(turn, {"flow": "add", "step": "link"}, text=args)
            return
        turn.reply("Send the Vinted link (or a short title if there is no link).")

    def _listing_arg(
        self, turn: Turn, args: str, usage: str, *, amount_first: bool = False
    ) -> tuple[Listing, str]:
        """The listing a command is about: ``#12``/``12``, else the one you are working on."""
        head, _, rest = args.strip().partition(" ")
        listing_id = parse_listing_ref(head) if head else None
        if listing_id is None and (not head or (amount_first and parse_amount(head))):
            listing_id, rest = turn.focused_listing_id(), args.strip()
        if listing_id is None:
            raise ValidationFailedError(f"Usage: {usage}")
        listing = turn.session.get(Listing, listing_id)
        if listing is None:
            raise NotFoundError(f"There is no listing #{listing_id}.")
        return listing, rest.strip()

    def _cmd_check(self, turn: Turn, args: str) -> None:
        listing, _ = self._listing_arg(turn, args, "/check 12")
        self._request_evaluation(turn, listing, trigger="manual")

    def _cmd_price(self, turn: Turn, args: str) -> None:
        listing, rest = self._listing_arg(turn, args, "/price 12 £40", amount_first=True)
        amount = parse_amount(rest) if rest else None
        if amount is None:
            raise ValidationFailedError("Usage: /price 12 £40")
        if not self._set_price(turn, listing, amount):
            turn.reply(f"{_listing_label(listing)} already has that price.")
            return
        self._request_evaluation(turn, listing, trigger="price_change")

    def _cmd_sold(self, turn: Turn, args: str) -> None:
        listing, _ = self._listing_arg(turn, args, "/sold 12")
        if existing_purchase_for_listing(turn.session, listing.id) is not None:
            raise InvalidStateError(
                f"You recorded buying #{listing.id} — it is in your inventory, not a market sale."
            )
        result = update_listing(turn.session, listing.id, now=turn.now, status=ListingStatus.SOLD)
        if not result.status_changed:
            turn.reply(f"#{listing.id} is already marked sold.")
            return
        observation = record_sold_observation(
            turn.session, result.listing, sold_at=turn.now, actor=turn.actor
        )
        if observation is not None:
            turn.reply(
                f"Marked #{listing.id} sold. Its last asking price "
                f"({_money(observation.sale_price, observation.currency)}) is saved as market "
                "data (with a discount, since sold prices are often lower)."
            )
        else:
            turn.reply(
                f"Marked #{listing.id} sold. It was not saved as market data (no price, or the "
                "brand/category was not identified)."
            )

    def _cmd_gone(self, turn: Turn, args: str) -> None:
        listing, _ = self._listing_arg(turn, args, "/gone 12")
        update_listing(turn.session, listing.id, now=turn.now, status=ListingStatus.REMOVED)
        turn.reply(f"Marked #{listing.id} removed.")

    def _cmd_show(self, turn: Turn, args: str) -> None:
        listing, _ = self._listing_arg(turn, args, "/show 12")
        evaluation = latest_evaluation(turn.session, listing.id)
        if evaluation is None:
            turn.reply(
                f"{_listing_label(listing)} has not been evaluated yet.",
                evaluate_keyboard(listing.id),
            )
            return
        self._send_result(turn, evaluation)

    def _send_result(self, turn: Turn, evaluation: ListingEvaluation) -> None:
        view = build_alert_view(
            turn.session, evaluation, now=turn.now, base_currency=self.settings.base_currency
        )
        alert = latest_alert_for_listing(turn.session, evaluation.listing_id)
        keyboard = None
        if alert is not None and alert.evaluation_id == evaluation.id:
            chosen = UserDecision(alert.user_decision) if alert.user_decision else None
            keyboard = decision_keyboard(alert.id, chosen=chosen, url=view.url)
        turn.reply(format_alert(view), keyboard)

    def _cmd_recent(self, turn: Turn, _args: str) -> None:
        listings = list(
            turn.session.scalars(
                select(Listing)
                .where(Listing.submitted_by_user_id == turn.user.id)
                .order_by(Listing.first_seen_at.desc(), Listing.id.desc())
                .limit(8)
            )
        )
        if not listings:
            turn.reply("No listings yet. Paste a Vinted link to start.")
            return
        lines = ["<b>Your latest listings</b>"]
        for listing in listings:
            evaluation = latest_evaluation(turn.session, listing.id)
            decision = evaluation.decision.replace("_", " ") if evaluation else "not evaluated"
            status = "" if listing.status == ListingStatus.ACTIVE.value else f" ({listing.status})"
            lines.append(f"{_listing_label(listing)} — {esc(decision)}{esc(status)}")
        turn.reply("\n".join(lines))

    def _cmd_comp(self, turn: Turn, args: str) -> None:
        if not args:
            turn.set_conversation({"flow": "comp"})
            turn.reply(
                "Send the sold item as one line:\n"
                f"<code>{esc(COMP_FORMAT)}</code>\n"
                f"For example: <code>{esc(COMP_EXAMPLE)}</code>\n"
                "Only record prices it actually sold for."
            )
            return
        self._record_comp(turn, args)

    def _record_comp(self, turn: Turn, text: str) -> None:
        comp = parse_comp(text, now=turn.now)
        bundle = ConfigService(turn.session).bundle()
        raw = RawSale(
            source=SaleSource.MANUAL_ENTRY,
            brand=comp.brand,
            category=comp.category,
            title=f"{comp.brand} {comp.category}"[:300],
            size=comp.size,
            condition=comp.condition,
            sale_price=comp.price,
            currency=comp.currency or self.settings.base_currency,
            sold_at=comp.sold_at,
            marketplace=self.settings.default_marketplace,
            notes="recorded in Telegram",
        )
        row, created = record_sale(
            turn.session, raw, catalogue=load_catalogue(turn.session),
            identification=bundle.identification, sizes=bundle.sizes, actor=turn.actor,
        )  # fmt: skip
        turn.end_conversation()
        if not created:
            turn.reply(f"That sale is already recorded (#{row.id}).")
            return
        condition = f" · {Condition(row.condition).label}" if row.condition else ""
        size = f" · size {esc(row.size_normalised)}" if row.size_normalised else ""
        turn.reply(
            f"Saved market sale #{row.id}: {_money(row.sale_price, row.currency)}{size}"
            f"{condition}, sold {row.sold_at:%d %b %Y}."
        )

    # ------------------------------------------------------------------ listing intake

    def _ingest_text(self, turn: Turn, text: str) -> tuple[IngestResult, bool]:
        """Save a listing from free text. Returns the result and whether the price is known."""
        raw, _ = raw_listing_from_text(
            text,
            base_currency=self.settings.base_currency,
            default_marketplace=self.settings.default_marketplace,
        )
        result = ingest_listing(
            turn.session, raw, source="telegram", now=turn.now, user_id=turn.user.id
        )
        turn.focus(result.listing.id)
        return result, result.listing.price is not None

    def _quick_add(self, turn: Turn, text: str) -> None:
        result, has_price = self._ingest_text(turn, text)
        listing = result.listing
        if listing.status not in LIVE:
            turn.reply(f"{_listing_label(listing)} is marked {listing.status}; not evaluating it.")
            return
        if not has_price:
            turn.set_conversation({"flow": "price", "listing_id": listing.id})
            verb = "Saved" if result.created else "Found"
            turn.reply(
                f"{verb} {_listing_label(listing)}. What is the asking price? "
                "(e.g. <code>£45</code>)"
            )
            return
        if not result.needs_evaluation:
            turn.reply(
                f"I already have {_listing_label(listing)} and nothing changed. "
                f"/show {listing.id} for the result, /check {listing.id} to re-evaluate."
            )
            return
        self._request_evaluation(turn, listing, trigger="ingest" if result.created else "manual")

    def _set_price(self, turn: Turn, listing: Listing, amount: tuple[Decimal, str | None]) -> bool:
        """Record an asking price. A bare number is in the listing's currency (or its Vinted
        site's, or your base currency)."""
        currency = amount[1] or listing.currency
        if currency is None and listing.url:
            ref = parse_item_url(listing.url)
            currency = ref.default_currency if ref else None
        result = update_listing(
            turn.session,
            listing.id,
            now=turn.now,
            price=amount[0],
            currency=currency or self.settings.base_currency,
        )
        return result.price_changed

    def _request_evaluation(self, turn: Turn, listing: Listing, *, trigger: str) -> None:
        if listing.status not in LIVE:
            raise InvalidStateError(f"#{listing.id} is marked {listing.status}.")
        if listing.price is None:
            turn.set_conversation({"flow": "price", "listing_id": listing.id})
            turn.reply(f"What is the asking price of {_listing_label(listing)}?")
            return
        turn.outbox.evaluate(listing.id, trigger)
        turn.focus(listing.id)
        turn.reply(f"Checking {_listing_label(listing)}… the result follows shortly.")

    # ------------------------------------------------------------------ conversations

    def _continue(
        self,
        turn: Turn,
        conversation: dict[str, Any],
        *,
        text: str | None = None,
        choice: str | None = None,
    ) -> None:
        flow = conversation.get("flow")
        if choice == "cancel":
            turn.end_conversation()
            turn.reply("Cancelled.")
            return
        if flow == "price":
            self._flow_price(turn, conversation, text)
        elif flow == "add":
            self._flow_add(turn, conversation, text, choice)
        elif flow == "buy":
            self._flow_buy(turn, conversation, text, choice)
        elif flow == "comp":
            if text is None:
                turn.reply("Send the sale as one line, or /cancel.")
                return
            self._record_comp(turn, text)
        else:
            turn.end_conversation()

    def _conversation_listing(self, turn: Turn, conversation: dict[str, Any]) -> Listing | None:
        """The listing a conversation is about; if it has gone, the conversation ends."""
        listing_id = conversation.get("listing_id")
        listing = turn.session.get(Listing, listing_id) if isinstance(listing_id, int) else None
        if listing is None:
            turn.end_conversation()
            turn.reply("That listing no longer exists; start again with the link.")
        return listing

    def _flow_price(self, turn: Turn, conversation: dict[str, Any], text: str | None) -> None:
        listing = self._conversation_listing(turn, conversation)
        if listing is None:
            return
        amount = parse_amount(text or "")
        if amount is None:
            turn.reply(
                "Send just the price, e.g. <code>45</code> or <code>£45.50</code> (or /cancel)."
            )
            return
        self._set_price(turn, listing, amount)
        turn.end_conversation()
        self._request_evaluation(turn, listing, trigger="ingest")

    # step-by-step entry ------------------------------------------------------------

    def _flow_add(
        self, turn: Turn, conversation: dict[str, Any], text: str | None, choice: str | None
    ) -> None:
        step = conversation.get("step")
        if step == "link":
            if text is None:
                turn.reply("Send the link or a title (or /cancel).")
                return
            result, has_price = self._ingest_text(turn, text)
            conversation = {"flow": "add", "listing_id": result.listing.id}
            self._ask(turn, conversation, "price" if not has_price else "brand")
            return

        listing = self._conversation_listing(turn, conversation)
        if listing is None:
            return
        skip = choice == "skip"
        if step == "price":
            amount = parse_amount(text or "")
            if amount is None:
                turn.reply("Send just the price, e.g. <code>45</code> (or /cancel).")
                return
            self._set_price(turn, listing, amount)
            self._ask(turn, conversation, "brand")
        elif step == "brand":
            if not skip:
                set_listing_details(turn.session, listing.id, now=turn.now, raw_brand=text)
            self._ask(turn, conversation, "size")
        elif step == "size":
            if not skip:
                set_listing_details(turn.session, listing.id, now=turn.now, raw_size=text)
            self._ask(turn, conversation, "condition")
        elif step == "condition":
            if not skip:
                condition = match_condition_label(choice or text)
                if condition is None:
                    turn.reply("Pick a condition below, or Skip.", condition_keyboard())
                    return
                set_listing_details(
                    turn.session, listing.id, now=turn.now, raw_condition=condition.label
                )
            self._ask(turn, conversation, "photos")
        elif step == "photos":
            if text and text.strip().lower() in {"done", "evaluate", "go", "ok"}:
                turn.end_conversation()
                self._request_evaluation(turn, listing, trigger="ingest")
            else:
                turn.reply(
                    "Send photos, or tap Evaluate now when you are ready.",
                    evaluate_keyboard(listing.id),
                )
        else:
            turn.end_conversation()

    def _ask(self, turn: Turn, conversation: dict[str, Any], step: str) -> None:
        turn.set_conversation({**conversation, "step": step})
        listing_id = conversation["listing_id"]
        if step == "price":
            turn.reply(f"Saved #{listing_id}. What is the asking price? (e.g. <code>£45</code>)")
        elif step == "brand":
            turn.reply("Brand? (e.g. Stone Island)", skip_keyboard())
        elif step == "size":
            turn.reply("Size? (e.g. L, 32W, UK 9)", skip_keyboard())
        elif step == "condition":
            turn.reply("Condition?", condition_keyboard())
        elif step == "photos":
            turn.reply(
                "Send photos now (labels, badges and tags help the authenticity check), then "
                "tap Evaluate now.",
                evaluate_keyboard(listing_id),
            )

    # purchase confirmation ---------------------------------------------------------

    def _start_purchase(self, turn: Turn, alert: Alert) -> None:
        existing = existing_purchase_for_listing(turn.session, alert.listing_id)
        if existing is not None:
            turn.reply(f"Purchase #{existing.id} is already recorded for #{alert.listing_id}.")
            return
        turn.set_conversation(
            {
                "flow": "buy",
                "step": "price",
                "alert_id": alert.id,
                "listing_id": alert.listing_id,
                "evaluation_id": alert.evaluation_id,
            }
        )
        turn.reply(format_decision_note(UserDecision.BUY))

    def _flow_buy(
        self, turn: Turn, conversation: dict[str, Any], text: str | None, choice: str | None
    ) -> None:
        listing = self._conversation_listing(turn, conversation)
        if listing is None:
            return
        currency = listing.currency or self.settings.base_currency
        if conversation.get("step") == "price":
            amount = parse_amount(text or "")
            if amount is None:
                turn.reply("Send the item price you paid, e.g. <code>£45</code> (or /cancel).")
                return
            if amount[1] and amount[1] != currency:
                raise ValidationFailedError(f"This listing is priced in {currency}.")
            fees = ConfigService(turn.session).bundle().fees
            costs = estimate_costs(amount[0], currency, fees)
            self._confirm_purchase(turn, conversation, costs, currency)
            return

        costs = PurchaseCosts(
            purchase_price=Decimal(conversation["price"]),
            buyer_fee=Decimal(conversation["fee"]),
            inbound_shipping=Decimal(conversation["shipping"]),
        )
        if choice == "ok":
            self._save_purchase(turn, conversation, listing, costs, currency)
            return
        amounts = parse_amounts(text or "")
        if len(amounts) == 1:  # the total actually paid
            costs = with_total_paid(costs, amounts[0])
        elif len(amounts) == 2:  # fee and postage
            costs = PurchaseCosts(
                purchase_price=costs.purchase_price,
                buyer_fee=amounts[0],
                inbound_shipping=amounts[1],
            )
        else:
            turn.reply(
                "Tap Confirm, or send the total you paid (e.g. <code>51.20</code>), or the fee "
                "and postage (e.g. <code>2.95 3.49</code>).",
                confirm_keyboard(),
            )
            return
        self._confirm_purchase(turn, conversation, costs, currency)

    def _confirm_purchase(
        self, turn: Turn, conversation: dict[str, Any], costs: PurchaseCosts, currency: str
    ) -> None:
        turn.set_conversation(
            {
                **conversation,
                "step": "confirm",
                "price": str(costs.purchase_price),
                "fee": str(costs.buyer_fee),
                "shipping": str(costs.inbound_shipping),
            }
        )
        turn.reply(
            f"Item {_money(costs.purchase_price, currency)} + Buyer Protection "
            f"{_money(costs.buyer_fee, currency)} + postage "
            f"{_money(costs.inbound_shipping, currency)} = "
            f"<b>{_money(costs.total, currency)}</b>\n"
            "Tap Confirm if that is what you paid, or send the actual total "
            "(e.g. <code>51.20</code>) or the fee and postage (e.g. <code>2.95 3.49</code>).",
            confirm_keyboard(),
        )

    def _save_purchase(
        self,
        turn: Turn,
        conversation: dict[str, Any],
        listing: Listing,
        costs: PurchaseCosts,
        currency: str,
    ) -> None:
        evaluation_id = conversation.get("evaluation_id")
        evaluation = (
            turn.session.get(ListingEvaluation, evaluation_id)
            if isinstance(evaluation_id, int)
            else None
        )
        purchase, item = record_purchase(
            turn.session,
            listing=listing,
            costs=costs,
            currency=currency,
            purchased_at=turn.now,
            actor=turn.actor,
            evaluation=evaluation,
            alert_id=conversation.get("alert_id"),
        )
        turn.end_conversation()
        expected = ""
        if item.expected_resale_price is not None:
            expected = f" Expected resale {_money(item.expected_resale_price, currency)}"
            if item.expected_profit is not None:
                expected += f", expected profit {_money(item.expected_profit, currency)}"
            expected += " (estimates)."
        turn.reply(
            f"Recorded purchase #{purchase.id}: total "
            f"{_money(purchase.total_acquisition_cost, currency)}. "
            f"It is item {item.id} in your stock (ordered) — /received {item.id} when it "
            f"arrives.{expected}"
        )

    # ------------------------------------------------------------------ photos

    def _on_photo(self, turn: Turn, message: TgMessage) -> None:
        listing, created_from_caption = self._photo_target(turn, message)
        if listing is None:
            turn.reply("Send the listing link first, or put the link in the photo caption.")
            return
        data, file_id, unique_id = self._download(message)
        stored = add_listing_image(
            turn.session,
            listing,
            data,
            media_dir=self.settings.media_dir,
            max_bytes=self.settings.max_image_bytes,
            max_images=self.settings.max_images_per_listing,
            source="telegram",
            telegram_file_id=file_id,
            telegram_file_unique_id=unique_id,
        )
        turn.focus(listing.id)
        first_of_group = True
        if message.media_group_id:
            key = state.media_group_key(message.media_group_id)
            first_of_group = state.get_value(turn.session, key, now=turn.now) is None
            state.set_value(
                turn.session,
                key,
                {"listing_id": listing.id},
                now=turn.now,
                ttl=state.MEDIA_GROUP_TTL,
            )
        if not first_of_group:
            return
        conversation = turn.conversation()
        if conversation and conversation.get("flow") == "add":
            if conversation.get("listing_id") != listing.id:  # /add, then a photo with the link
                self._ask(
                    turn,
                    {"flow": "add", "listing_id": listing.id},
                    "price" if listing.price is None else "brand",
                )
                return
            if listing.price is None:
                turn.reply("Photo saved. What is the asking price? (e.g. <code>£45</code>)")
                turn.set_conversation({**conversation, "step": "price"})
                return
        if created_from_caption and listing.price is None:
            turn.set_conversation({"flow": "price", "listing_id": listing.id})
            turn.reply(
                f"Saved {_listing_label(listing)} with your photos. What is the asking price?"
            )
            return
        note = "" if stored.created else " (I already had that photo)"
        turn.reply(
            f"Photos go with {_listing_label(listing)}{note}. Send any more, then tap "
            "Evaluate now.",
            evaluate_keyboard(listing.id),
        )

    def _photo_target(self, turn: Turn, message: TgMessage) -> tuple[Listing | None, bool]:
        if message.media_group_id:
            group = state.get_value(
                turn.session, state.media_group_key(message.media_group_id), now=turn.now
            )
            listing_id = (group or {}).get("listing_id")
            if isinstance(listing_id, int):
                return turn.session.get(Listing, listing_id), False
        caption = message.caption or ""
        if caption and find_item_url(caption) is not None:
            result, _ = self._ingest_text(turn, caption)
            return result.listing, True
        conversation = turn.conversation() or {}
        conv_listing = conversation.get("listing_id")
        if isinstance(conv_listing, int):
            return turn.session.get(Listing, conv_listing), False
        if conversation.get("flow") == "add":
            return None, False  # /add is waiting for the link: don't guess an older listing
        focused = turn.focused_listing_id()
        if focused is not None:
            return turn.session.get(Listing, focused), False
        return None, False

    def _download(self, message: TgMessage) -> tuple[bytes, str, str | None]:
        """The largest version of the photo within the size limit: (bytes, file ID, unique ID)."""
        if self.client is None:
            raise ExternalServiceError("Telegram is not configured.")
        limit = self.settings.max_image_bytes
        chosen: tuple[str, str | None] | None = None
        if message.photo:
            sizes = sorted(message.photo, key=lambda p: p.width * p.height, reverse=True)
            fitting = [p for p in sizes if p.file_size is None or p.file_size <= limit]
            if fitting:
                chosen = (fitting[0].file_id, fitting[0].file_unique_id)
        elif message.document is not None:
            document = message.document
            if document.file_size is None or document.file_size <= limit:
                chosen = (document.file_id, document.file_unique_id)
        if chosen is None:
            raise ValidationFailedError(f"That image is larger than {limit // (1024 * 1024)} MB.")
        file_id, unique_id = chosen
        try:
            info = self.client.get_file(file_id)
            file_path = info.get("file_path")
            if not isinstance(file_path, str):
                raise ExternalServiceError("Telegram did not return the photo; please resend it.")
            return self.client.download_file(file_path, max_bytes=limit), file_id, unique_id
        except FileTooLargeError as exc:
            raise ValidationFailedError(exc.description) from None
        except TelegramError as exc:
            log.warning("telegram_photo_download_failed", error=exc.description)
            raise ExternalServiceError(
                "I couldn't download that photo from Telegram; please send it again."
            ) from None

    # ------------------------------------------------------------------ buttons

    def _on_callback(self, turn: Turn, query: TgCallbackQuery) -> None:
        callback = parse_callback(query.data)
        if callback is None:
            turn.outbox.answer(query.id, "This button is no longer valid.")
            return
        if callback.kind == "noop":
            turn.outbox.answer(query.id)
        elif callback.kind == "decision":
            self._on_decision(turn, query, callback)
        elif callback.kind == "evaluate":
            self._on_evaluate_button(turn, query, callback)
        else:
            self._on_form_button(turn, query, callback)

    def _on_decision(self, turn: Turn, query: TgCallbackQuery, callback: Callback) -> None:
        assert callback.id is not None
        assert callback.decision is not None
        alert = record_decision(
            turn.session, callback.id, callback.decision, actor=turn.actor, now=turn.now
        )
        listing = turn.session.get(Listing, alert.listing_id)
        if query.message is not None:
            turn.outbox.edit_markup(
                query.message.chat.id,
                query.message.message_id,
                decision_keyboard(
                    alert.id, chosen=callback.decision, url=listing.url if listing else None
                ),
            )
        turn.outbox.answer(query.id, f"Marked {DECISION_WORDS[callback.decision]}")
        conversation = turn.conversation()
        if callback.decision is UserDecision.BUY:
            self._start_purchase(turn, alert)
        elif conversation and conversation.get("alert_id") == alert.id:
            turn.end_conversation()
            turn.reply(f"Marked {DECISION_WORDS[callback.decision]}; purchase entry cancelled.")

    def _on_evaluate_button(self, turn: Turn, query: TgCallbackQuery, callback: Callback) -> None:
        assert callback.id is not None
        listing = turn.session.get(Listing, callback.id)
        if listing is None:
            raise NotFoundError(f"There is no listing #{callback.id}.")
        conversation = turn.conversation()
        if conversation and conversation.get("listing_id") == listing.id:
            turn.end_conversation()
        if query.message is not None:
            turn.outbox.edit_markup(query.message.chat.id, query.message.message_id, None)
        turn.outbox.answer(query.id, "Evaluating…")
        self._request_evaluation(turn, listing, trigger="manual")

    def _on_form_button(self, turn: Turn, query: TgCallbackQuery, callback: Callback) -> None:
        conversation = turn.conversation()
        if conversation is None:
            turn.outbox.answer(query.id, "That question has expired.")
            if query.message is not None:
                turn.outbox.edit_markup(query.message.chat.id, query.message.message_id, None)
            return
        if query.message is not None:
            turn.outbox.edit_markup(query.message.chat.id, query.message.message_id, None)
        turn.outbox.answer(query.id)
        self._continue(turn, conversation, choice=callback.value or "")
