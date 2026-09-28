"""Alert text, escaping, keyboards and callback data."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.core.enums import CompLevel, Decision, UserDecision
from app.notifications.telegram.formatter import (
    DISCLAIMER,
    AlertView,
    choice_keyboard,
    condition_keyboard,
    decision_keyboard,
    evaluate_keyboard,
    format_alert,
    format_decision_note,
    liquidity_label,
    parse_callback,
    safe_url,
    short_url,
)

D = Decimal


def view(**overrides) -> AlertView:
    data = {
        "decision": Decision.HIGH_PRIORITY,
        "listing_id": 12,
        "headline": "Garment-dyed crewneck sweatshirt",
        "currency": "GBP",
        "brand": "Stone Island",
        "size": "L",
        "condition": "Very good",
        "colour": "Navy",
        "price": D("45.00"),
        "max_buy": D("62.00"),
        "expected": D("110.00"),
        "quick": D("90.00"),
        "optimistic": D("130.00"),
        "comp_count": 14,
        "comp_level": CompLevel.L2,
        "estimate_confidence": D("0.78"),
        "total_investment": D("49.95"),
        "expected_profit": D("38.20"),
        "roi": D("0.7648"),
        "median_days": D("9.0"),
        "liquidity": D("0.82"),
        "product_confidence": D("0.86"),
        "auth_risk": D("0.35"),
        "auth_level": "medium",
        "auth_confidence": D("0.50"),
        "auth_note": "no label photo",
        "url": "https://www.vinted.co.uk/items/4829301234-stone-island-crewneck",
        "seen": "Listed 6 min ago",
    }
    data.update(overrides)
    return AlertView(**data)


def test_plan_layout():
    """The example layout from the architecture plan (section 5.8)."""
    assert format_alert(view()).split("\n") == [
        "🟢 <b>HIGH</b> · Stone Island · Garment-dyed crewneck sweatshirt",
        "Size L · Very good · Navy",
        "Price £45.00  ·  Max buy £62.00",
        "Resale est. £110 (quick £90 · optimistic £130) — 14 comps, "
        "product+size+condition, conf 0.78",
        "Total investment £49.95 · Exp. profit £38.20 · ROI 76%",
        "Median sale time 9 days · Liquidity high",
        "Product conf 0.86 · Auth risk MEDIUM 0.35 (conf 0.50): no label photo",
        'Listed 6 min ago · <a href="https://www.vinted.co.uk/items/4829301234-stone-island-'
        'crewneck">vinted.co.uk/items/4829301234-stone…</a> · #12',
        f"<i>{DISCLAIMER}</i>",
    ]


def test_everything_from_the_listing_is_escaped():
    text = format_alert(
        view(
            headline="<script>alert(1)</script> & co",
            brand="A&B",
            size="<L>",
            auth_note="<b>x</b>",
            reasons=("price < cap & more",),
            decision=Decision.REVIEW,
            checks=("<i>check</i>",),
        )
    )
    assert "<script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt; &amp; co" in text
    assert "A&amp;B" in text
    assert "Size &lt;L&gt;" in text
    assert "&lt;b&gt;x&lt;/b&gt;" in text
    assert "Price &lt; cap &amp; more" not in text  # reasons are capitalised...
    assert "price &lt; cap &amp; more" in text  # ...only by the service, not here
    assert "&lt;i&gt;check&lt;/i&gt;" in text


def test_rejected_shows_why_but_no_checks():
    text = format_alert(
        view(
            decision=Decision.REJECTED,
            reasons=("Expected profit 12.00 < minimum 25",),
            checks=("Ask for a photo of the label",),
        )
    )
    assert text.startswith("🔴 <b>NOT A DEAL</b>")
    assert "<b>Why:</b>\n• Expected profit 12.00 &lt; minimum 25" in text
    assert "Before buying" not in text


def test_review_shows_reasons_and_checks_with_limits():
    reasons = tuple(f"reason {i}" for i in range(6))
    checks = tuple(f"check {i}" for i in range(5))
    text = format_alert(view(decision=Decision.REVIEW, reasons=reasons, checks=checks))
    assert text.startswith("🟡 <b>REVIEW</b>")
    assert text.count("• reason") == 4
    assert text.count("• check") == 3


def test_normal_notes():
    text = format_alert(view(decision=Decision.NORMAL, reasons=("no sale-speed data",)))
    assert text.startswith("🔵 <b>DEAL</b>")
    assert "<b>Notes:</b>" in text


def test_sparse_view_omits_missing_lines():
    text = format_alert(
        AlertView(
            decision=Decision.REJECTED,
            listing_id=3,
            headline="Mystery jacket",
            currency="GBP",
            reasons=("Brand not identified",),
        )
    )
    assert text.split("\n") == [
        "🔴 <b>NOT A DEAL</b> · Mystery jacket",
        "<b>Why:</b>",
        "• Brand not identified",
        "#3",
        f"<i>{DISCLAIMER}</i>",
    ]


def test_price_guide_basis():
    text = format_alert(view(comp_level=CompLevel.GUIDE, comp_count=0))
    assert "— from your price guide, conf 0.78" in text


def test_non_gbp_and_fractional_days():
    text = format_alert(view(currency="EUR", median_days=D("1.0"), price=D("40")))
    assert "Price €40.00" in text
    assert "Median sale time 1.0 day" in text


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://www.vinted.co.uk/items/1", "https://www.vinted.co.uk/items/1"),
        ("javascript:alert(1)", None),
        ("ftp://example.com/x", None),
        ("https://", None),
        (None, None),
        ("http://[::1", None),
    ],
)
def test_safe_url(url, expected):
    assert safe_url(url) == expected


def test_unsafe_url_is_not_linked():
    text = format_alert(view(url="javascript:alert(1)"))
    assert "href" not in text
    assert "javascript" not in text


def test_short_url():
    assert short_url("https://www.vinted.co.uk/items/1/") == "vinted.co.uk/items/1"


@pytest.mark.parametrize(
    ("score", "label"), [(D("0.9"), "high"), (D("0.5"), "medium"), (D("0.1"), "low")]
)
def test_liquidity_label(score, label):
    assert liquidity_label(score) == label


class TestCallbacks:
    def test_decision_round_trip(self):
        keyboard = decision_keyboard(123456789012, chosen=UserDecision.PASS, url=None)
        row = keyboard["inline_keyboard"][0]
        assert [b["text"] for b in row] == ["BUY", "✓ PASS", "REVIEW"]
        for button, decision in zip(row, UserDecision, strict=True):
            parsed = parse_callback(button["callback_data"])
            assert parsed is not None
            assert (parsed.kind, parsed.id, parsed.decision) == ("decision", 123456789012, decision)
            assert len(button["callback_data"].encode()) <= 64

    def test_link_button_only_for_safe_urls(self):
        assert (
            len(decision_keyboard(1, url="https://www.vinted.co.uk/items/1")["inline_keyboard"])
            == 2
        )
        assert len(decision_keyboard(1, url="javascript:x")["inline_keyboard"]) == 1

    def test_other_kinds(self):
        evaluate = parse_callback(evaluate_keyboard(7)["inline_keyboard"][0][0]["callback_data"])
        assert evaluate is not None
        assert (evaluate.kind, evaluate.id) == ("evaluate", 7)
        form = parse_callback("f:very_good")
        assert form is not None
        assert (form.kind, form.value) == ("form", "very_good")
        noop = parse_callback("n")
        assert noop is not None
        assert noop.kind == "noop"

    @pytest.mark.parametrize(
        "data", [None, "", "a:1:x", "a:x:b", "e:", "f:DROP TABLE", "x:1", "a:1:b:extra", "e:1\n"]
    )
    def test_invalid(self, data):
        assert parse_callback(data) is None

    def test_keyboards(self):
        conditions = condition_keyboard()["inline_keyboard"]
        flat = [b["callback_data"] for row in conditions for b in row]
        assert "f:very_good" in flat
        assert flat[-1] == "f:skip"
        grid = choice_keyboard([("a", "a"), ("b", "b"), ("c", "c")], columns=2)["inline_keyboard"]
        assert [len(r) for r in grid] == [2, 1]


def test_buy_note_says_nothing_was_bought():
    note = format_decision_note(UserDecision.BUY)
    assert "Nothing has been bought" in note
    assert format_decision_note(UserDecision.PASS) == "Marked <b>PASS</b>."
