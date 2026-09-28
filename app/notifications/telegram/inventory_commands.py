"""Stock and sales commands for the chat: /stock /item /received /listed /sale /shipped /done
/writeoff /stats. Inventory items are referred to by their item number (``7`` or ``i7``),
listings by ``#12``."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.analysis.analytics import Period, stock_snapshot, summarise
from app.analysis.inventory.lifecycle import IN_STOCK
from app.core.enums import InventoryStatus
from app.core.errors import ValidationFailedError
from app.core.money import format_money, format_percent
from app.core.time import days_between
from app.models import InventoryItem, PredictionResult
from app.notifications.telegram.formatter import clip, esc
from app.notifications.telegram.parsing import parse_amount
from app.services.analytics import item_records
from app.services.config_service import ConfigService
from app.services.inventory import get_item, record_resale, transition_item

if TYPE_CHECKING:
    from app.notifications.telegram.handlers import BotHandler, Turn

Command = Callable[["Turn", str], None]
_ITEM_RE = re.compile(r"^i?(\d{1,12})$", re.IGNORECASE)
STOCK_LIST_LIMIT = 15


def _item_ref(args: str, usage: str) -> tuple[int, str]:
    head, _, rest = args.strip().partition(" ")
    match = _ITEM_RE.match(head)
    if match is None:
        raise ValidationFailedError(f"Usage: {usage}")
    return int(match.group(1)), rest.strip()


def _label(item: InventoryItem) -> str:
    return f"item {item.id} {esc(clip(item.title, 50))}"


class InventoryCommands:
    def __init__(self, handler: BotHandler) -> None:
        self.handler = handler

    @property
    def commands(self) -> dict[str, Command]:
        return {
            "stock": self.stock,
            "item": self.item,
            "received": self.received,
            "listed": self.listed,
            "sale": self.sale,
            "shipped": self.shipped,
            "done": self.done,
            "writeoff": self.write_off,
            "stats": self.stats,
        }

    def _money(self, value: Decimal, currency: str | None = None) -> str:
        return format_money(value, currency or self.handler.settings.base_currency)

    # ------------------------------------------------------------------ views

    def stock(self, turn: Turn, _args: str) -> None:
        currency = self.handler.settings.base_currency
        records, _ = item_records(turn.session, currency)
        snapshot = stock_snapshot(records, today=turn.now.date())
        if snapshot.items == 0:
            turn.reply("No stock. Items appear here once you record a purchase.")
            return
        lines = [
            f"<b>Stock:</b> {snapshot.items} items, {self._money(snapshot.capital)} tied up",
        ]
        if snapshot.expected_value:
            lines.append(f"Expected resale value {self._money(snapshot.expected_value)} (estimate)")
        items = turn.session.scalars(
            select(InventoryItem)
            .where(
                InventoryItem.status.in_([s.value for s in IN_STOCK]),
                InventoryItem.currency == currency,
            )
            .order_by(InventoryItem.id)
            .limit(STOCK_LIST_LIMIT)
        )
        for item in items:
            held = days_between(item.purchase.purchased_at, turn.now)
            price = f" {self._money(item.listed_price, item.currency)}" if item.listed_price else ""
            lines.append(f"{_label(item)} — {item.status.replace('_', ' ')}{price} · {held} days")
        if snapshot.items > STOCK_LIST_LIMIT:
            lines.append(
                f"…and {snapshot.items - STOCK_LIST_LIMIT} more (see /inventory in the API)"
            )
        turn.reply("\n".join(lines))

    def item(self, turn: Turn, args: str) -> None:
        item_id, _ = _item_ref(args, "/item 7")
        item = get_item(turn.session, item_id)
        cur = item.currency
        extras = item.total_cost_basis - item.allocated_acquisition_cost
        cost = (
            f"Cost {self._money(item.total_cost_basis, cur)} (purchase share "
            f"{self._money(item.allocated_acquisition_cost, cur)}"
        )
        cost += f", extras {self._money(extras, cur)})" if extras else ")"
        lines = [
            f"<b>{_label(item)}</b> — {item.status.replace('_', ' ')}",
            cost,
            f"Held {days_between(item.purchase.purchased_at, turn.now)} days",
        ]
        if item.expected_resale_price is not None:
            lines.append(
                f"Expected resale {self._money(item.expected_resale_price, cur)} (estimate)"
            )
        if item.listed_price is not None:
            lines.append(f"Listed at {self._money(item.listed_price, cur)}")
        if item.resale is not None:
            profit = item.resale.net_proceeds - item.total_cost_basis
            lines.append(
                f"Sold {self._money(item.resale.sale_price, cur)} on "
                f"{item.resale.sold_at:%d %b} · net {self._money(item.resale.net_proceeds, cur)}"
                f" · profit {self._money(profit, cur)}"
            )
        turn.reply("\n".join(lines))

    def stats(self, turn: Turn, _args: str) -> None:
        currency = self.handler.settings.base_currency
        records, _ = item_records(turn.session, currency)
        today = turn.now.date()
        period = Period(start=today - timedelta(days=29), end=today)
        summary = summarise(records, period, today=today)
        stock = stock_snapshot(records, today=today)
        sales = summary.sales
        lines = [
            "<b>Last 30 days</b>",
            f"Bought {summary.items_bought} for {self._money(summary.spend)}",
            f"Sold {sales.items_sold} for {self._money(sales.revenue)} · profit "
            f"{self._money(sales.realised_profit)}"
            + (f" · ROI {format_percent(sales.roi)}" if sales.roi is not None else ""),
        ]
        if sales.average_days_to_sell is not None:
            lines.append(f"Average {sales.average_days_to_sell} days from purchase to sale")
        if summary.written_off or summary.returned:
            lines.append(
                f"Written off {summary.written_off} ({self._money(summary.write_off_loss)}), "
                f"returned {summary.returned}"
            )
        lines.append(f"Net result {self._money(summary.net_result)}")
        lines.append(f"Stock: {stock.items} items, {self._money(stock.capital)} tied up")
        turn.reply("\n".join(lines))

    # ------------------------------------------------------------------ changes

    def _move(self, turn: Turn, args: str, target: InventoryStatus, usage: str) -> InventoryItem:
        item_id, _ = _item_ref(args, usage)
        return transition_item(turn.session, item_id, target, at=turn.now, actor=turn.actor)

    def received(self, turn: Turn, args: str) -> None:
        item_id, rest = _item_ref(args, "/received 7 (optionally the condition)")
        item = transition_item(
            turn.session, item_id, InventoryStatus.RECEIVED, at=turn.now, actor=turn.actor,
            condition=rest or None,
        )  # fmt: skip
        turn.reply(f"{_label(item)} received.")

    def listed(self, turn: Turn, args: str) -> None:
        item_id, rest = _item_ref(args, "/listed 7 £99")
        amount = parse_amount(rest) if rest else None
        item = transition_item(
            turn.session, item_id, InventoryStatus.LISTED, at=turn.now, actor=turn.actor,
            listed_price=amount[0] if amount else None,
        )  # fmt: skip
        price = f" at {self._money(item.listed_price, item.currency)}" if item.listed_price else ""
        turn.reply(f"{_label(item)} listed{price}.")

    def shipped(self, turn: Turn, args: str) -> None:
        item = self._move(turn, args, InventoryStatus.SHIPPED, "/shipped 7")
        turn.reply(f"{_label(item)} shipped.")

    def done(self, turn: Turn, args: str) -> None:
        item = self._move(turn, args, InventoryStatus.COMPLETED, "/done 7")
        turn.reply(f"{_label(item)} completed.")

    def write_off(self, turn: Turn, args: str) -> None:
        item = self._move(turn, args, InventoryStatus.WRITTEN_OFF, "/writeoff 7")
        turn.reply(
            f"{_label(item)} written off: a loss of "
            f"{self._money(item.total_cost_basis, item.currency)}."
        )

    def sale(self, turn: Turn, args: str) -> None:
        item_id, rest = _item_ref(args, "/sale 7 £95")
        amount = parse_amount(rest) if rest else None
        if amount is None:
            raise ValidationFailedError("Usage: /sale 7 £95 (the price it sold for)")
        fees = ConfigService(turn.session).bundle().fees
        resale = record_resale(
            turn.session, item_id, sale_price=amount[0], sold_at=turn.now, actor=turn.actor,
            fees=fees, currency=amount[1],
        )  # fmt: skip
        item = get_item(turn.session, item_id)
        cur = resale.currency
        profit = resale.net_proceeds - item.total_cost_basis
        lines = [
            f"Sold {_label(item)} for {self._money(resale.sale_price, cur)}.",
            f"Net {self._money(resale.net_proceeds, cur)} after selling costs · profit "
            f"<b>{self._money(profit, cur)}</b>",
        ]
        prediction = turn.session.scalar(
            select(PredictionResult).where(PredictionResult.inventory_item_id == item.id)
        )
        if prediction is not None and prediction.predicted_expected_sale is not None:
            lines.append(
                f"Predicted {self._money(prediction.predicted_expected_sale, cur)}"
                + (
                    " — within the predicted range."
                    if prediction.actual_within_quick_optimistic
                    else " — outside the predicted range."
                )
            )
        if resale.market_sale_id is not None:
            lines.append("Added to your market data.")
        turn.reply("\n".join(lines))
