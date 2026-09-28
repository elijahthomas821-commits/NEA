"""Telegram message text (HTML parse mode) and inline keyboards.

Everything that came from a listing or the operator is escaped. Messages carry the standing
disclaimer: estimates are not guaranteed outcomes, and the system never buys anything.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import urlsplit

from app.core.enums import CompLevel, Condition, Decision, UserDecision
from app.core.money import format_money, format_money_short, format_percent

DISCLAIMER = "Estimates only — not guaranteed outcomes."
MAX_REASONS = 4
MAX_CHECKS = 3

_HEADERS = {
    Decision.HIGH_PRIORITY: "🟢 <b>HIGH</b>",
    Decision.NORMAL: "🔵 <b>DEAL</b>",
    Decision.REVIEW: "🟡 <b>REVIEW</b>",
    Decision.REJECTED: "🔴 <b>NOT A DEAL</b>",
}
_DECISION_LABELS = {
    UserDecision.BUY: "BUY",
    UserDecision.PASS: "PASS",
    UserDecision.REVIEW: "REVIEW",
}
_DECISION_CODES = {"b": UserDecision.BUY, "p": UserDecision.PASS, "r": UserDecision.REVIEW}


def esc(value: object, *, quote: bool = False) -> str:
    """Escape for Telegram HTML text; ``quote=True`` for attribute values."""
    return html.escape(str(value), quote=quote)


def clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# --------------------------------------------------------------------------- callback data
#
# Telegram limits callback data to 64 bytes. Formats:
#   a:<alert_id>:<b|p|r>   decision on an alert
#   e:<listing_id>         evaluate a listing now
#   f:<value>              answer to the current question (skip, ok, cancel, a condition)
#   n                      no-op (a label button)

_CALLBACK_RE = re.compile(
    r"^(?:a:(?P<alert>\d{1,12}):(?P<choice>[bpr])"
    r"|e:(?P<listing>\d{1,12})"
    r"|f:(?P<form>[a-z_]{1,30})"
    r"|(?P<noop>n))"
)


@dataclass(frozen=True)
class Callback:
    kind: Literal["decision", "evaluate", "form", "noop"]
    id: int | None = None
    value: str | None = None
    decision: UserDecision | None = None


def parse_callback(data: str | None) -> Callback | None:
    match = _CALLBACK_RE.fullmatch(data or "")
    if match is None:
        return None
    if match.group("alert"):
        return Callback(
            kind="decision",
            id=int(match.group("alert")),
            decision=_DECISION_CODES[match.group("choice")],
        )
    if match.group("listing"):
        return Callback(kind="evaluate", id=int(match.group("listing")))
    if match.group("form"):
        return Callback(kind="form", value=match.group("form"))
    return Callback(kind="noop")


def _button(text: str, data: str) -> dict[str, str]:
    return {"text": text, "callback_data": data}


def decision_keyboard(
    alert_id: int, *, chosen: UserDecision | None = None, url: str | None = None
) -> dict[str, Any]:
    """BUY / PASS / REVIEW, with the current choice ticked. BUY never buys anything."""
    row = []
    for code, decision in _DECISION_CODES.items():
        label = _DECISION_LABELS[decision]
        if decision is chosen:
            label = f"✓ {label}"
        row.append(_button(label, f"a:{alert_id}:{code}"))
    rows: list[list[dict[str, str]]] = [row]
    link = safe_url(url)
    if link:
        rows.append([{"text": "Open listing", "url": link}])
    return {"inline_keyboard": rows}


def evaluate_keyboard(listing_id: int) -> dict[str, Any]:
    return {"inline_keyboard": [[_button("Evaluate now", f"e:{listing_id}")]]}


def choice_keyboard(options: list[tuple[str, str]], *, columns: int = 2) -> dict[str, Any]:
    buttons = [_button(label, f"f:{value}") for label, value in options]
    return {"inline_keyboard": [buttons[i : i + columns] for i in range(0, len(buttons), columns)]}


def condition_keyboard() -> dict[str, Any]:
    options = [(c.label, c.value) for c in Condition]
    return choice_keyboard([*options, ("Skip", "skip")])


def skip_keyboard() -> dict[str, Any]:
    return choice_keyboard([("Skip", "skip")])


def confirm_keyboard() -> dict[str, Any]:
    return choice_keyboard([("Confirm", "ok"), ("Cancel", "cancel")])


# --------------------------------------------------------------------------- alert text


@dataclass(frozen=True)
class AlertView:
    decision: Decision
    listing_id: int
    headline: str
    currency: str
    brand: str | None = None
    size: str | None = None
    condition: str | None = None
    colour: str | None = None
    price: Decimal | None = None
    max_buy: Decimal | None = None
    expected: Decimal | None = None
    quick: Decimal | None = None
    optimistic: Decimal | None = None
    comp_count: int = 0
    comp_level: CompLevel | None = None
    estimate_confidence: Decimal | None = None
    total_investment: Decimal | None = None
    expected_profit: Decimal | None = None
    roi: Decimal | None = None
    median_days: Decimal | None = None
    liquidity: Decimal | None = None
    product_confidence: Decimal | None = None
    auth_risk: Decimal | None = None
    auth_level: str | None = None
    auth_confidence: Decimal | None = None
    auth_note: str | None = None
    reasons: tuple[str, ...] = field(default_factory=tuple)
    checks: tuple[str, ...] = field(default_factory=tuple)
    url: str | None = None
    seen: str | None = None


def safe_url(url: str | None) -> str | None:
    """Only plain http(s) links are ever rendered."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return url


def short_url(url: str) -> str:
    parts = urlsplit(url)
    host = parts.netloc.removeprefix("www.")
    path = parts.path.rstrip("/")
    text = host + path
    return text if len(text) <= 36 else text[:35] + "…"


def _conf(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01'))}"


def liquidity_label(score: Decimal) -> str:
    if score >= Decimal("0.7"):
        return "high"
    if score >= Decimal("0.4"):
        return "medium"
    return "low"


def _days(value: Decimal) -> str:
    rounded = value.quantize(Decimal(1)) if value >= 3 else value.quantize(Decimal("0.1"))
    return f"{rounded} day" if rounded == 1 else f"{rounded} days"


def format_alert(view: AlertView) -> str:
    cur = view.currency

    def money(value: Decimal) -> str:
        return format_money(value, cur)

    def short(value: Decimal) -> str:
        return format_money_short(value, cur)

    title_bits = [b for b in (view.brand, view.headline) if b]
    lines = [f"{_HEADERS[view.decision]} · {esc(clip(' · '.join(title_bits), 110))}"]

    item = [
        b for b in (f"Size {view.size}" if view.size else None, view.condition, view.colour) if b
    ]
    if item:
        lines.append(esc(" · ".join(item)))

    price_bits = []
    if view.price is not None:
        price_bits.append(f"Price {money(view.price)}")
    if view.max_buy is not None:
        price_bits.append(f"Max buy {money(view.max_buy)}")
    if price_bits:
        lines.append("  ·  ".join(price_bits))

    if view.expected is not None:
        est = f"Resale est. {short(view.expected)}"
        if view.quick is not None and view.optimistic is not None:
            est += f" (quick {short(view.quick)} · optimistic {short(view.optimistic)})"
        basis = []
        if view.comp_level is CompLevel.GUIDE:
            basis.append("from your price guide")
        elif view.comp_level is not None:
            basis.append(f"{view.comp_count} comps, {view.comp_level.description}")
        if view.estimate_confidence is not None:
            basis.append(f"conf {_conf(view.estimate_confidence)}")
        if basis:
            est += " — " + ", ".join(basis)
        lines.append(esc(est))

    money_bits = []
    if view.total_investment is not None:
        money_bits.append(f"Total investment {money(view.total_investment)}")
    if view.expected_profit is not None:
        money_bits.append(f"Exp. profit {money(view.expected_profit)}")
    if view.roi is not None:
        money_bits.append(f"ROI {format_percent(view.roi)}")
    if money_bits:
        lines.append(" · ".join(money_bits))

    speed = []
    if view.median_days is not None:
        speed.append(f"Median sale time {_days(view.median_days)}")
    if view.liquidity is not None:
        speed.append(f"Liquidity {liquidity_label(view.liquidity)}")
    if speed:
        lines.append(" · ".join(speed))

    trust = []
    if view.product_confidence is not None:
        trust.append(f"Product conf {_conf(view.product_confidence)}")
    if view.auth_risk is not None:
        auth = f"Auth risk {(view.auth_level or '').upper()} {_conf(view.auth_risk)}".replace(
            "  ", " "
        )
        if view.auth_confidence is not None:
            auth += f" (conf {_conf(view.auth_confidence)})"
        if view.auth_note:
            auth += f": {clip(view.auth_note, 90)}"
        trust.append(auth)
    if trust:
        lines.append(esc(" · ".join(trust)))

    if view.reasons:
        heading = "Why" if view.decision in (Decision.REJECTED, Decision.REVIEW) else "Notes"
        lines.append(f"<b>{heading}:</b>")
        lines.extend(f"• {esc(clip(r, 160))}" for r in view.reasons[:MAX_REASONS])
    if view.checks and view.decision is not Decision.REJECTED:
        lines.append("<b>Before buying:</b>")
        lines.extend(f"• {esc(clip(c, 160))}" for c in view.checks[:MAX_CHECKS])

    footer = [esc(view.seen)] if view.seen else []
    link = safe_url(view.url)
    if link:
        footer.append(f'<a href="{esc(link, quote=True)}">{esc(short_url(link))}</a>')
    footer.append(f"#{view.listing_id}")
    lines.append(" · ".join(footer))
    lines.append(f"<i>{DISCLAIMER}</i>")
    return "\n".join(lines)


def format_decision_note(decision: UserDecision) -> str:
    if decision is UserDecision.BUY:
        return (
            "Marked <b>BUY</b>. Nothing has been bought — buy it yourself on the marketplace, "
            "then send me the item price you paid (e.g. <code>£45</code>) to record it. "
            "/cancel if you decide not to."
        )
    return f"Marked <b>{_DECISION_LABELS[decision]}</b>."
