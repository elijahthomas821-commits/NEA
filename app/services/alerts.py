"""Alerts: whether to message you about an evaluation, and your BUY / PASS / REVIEW decisions.

Re-alert policy (``AlertMode``):

* ``always`` — you asked about this listing (sent it to the bot, uploaded photos, pressed
  "Evaluate now"): the result is always sent, including "not a deal".
* ``deals`` — bulk imports and automatic re-evaluations: only results worth a look are sent,
  and a listing you were already told about is only sent again when the decision improved or
  the price dropped materially (both ``min_price_drop_pct`` and ``min_price_drop_abs``).

There is exactly one alert row per evaluation and channel (unique constraint), so retried or
duplicated tasks can never send the same evaluation twice.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config.schemas import RealertRules
from app.core.enums import (
    AlertMode,
    AlertPriority,
    AlertStatus,
    CompLevel,
    Condition,
    Decision,
    ProductLevel,
    UserDecision,
)
from app.core.errors import NotFoundError
from app.core.time import humanize_age
from app.models import Alert, Brand, Listing, ListingEvaluation, Product
from app.notifications.telegram.formatter import AlertView
from app.services import audit
from app.services.audit import Actor

CHANNEL = "telegram"

_PRIORITY = {
    Decision.HIGH_PRIORITY: AlertPriority.HIGH,
    Decision.NORMAL: AlertPriority.NORMAL,
    Decision.REVIEW: AlertPriority.REVIEW,
    Decision.REJECTED: AlertPriority.INFO,
}


@dataclass(frozen=True)
class AlertPlan:
    send: bool
    priority: AlertPriority
    reason: str


@dataclass(frozen=True)
class PreviousAlert:
    decision: Decision
    price: Decimal | None


def priority_for(decision: Decision) -> AlertPriority:
    return _PRIORITY[decision]


def material_price_drop(old: Decimal | None, new: Decimal | None, rules: RealertRules) -> bool:
    if old is None or new is None:
        return False
    drop = old - new
    return drop >= rules.min_price_drop_abs and drop >= old * rules.min_price_drop_pct


def plan_alert(
    mode: AlertMode,
    decision: Decision,
    price: Decimal | None,
    previous: PreviousAlert | None,
    rules: RealertRules,
) -> AlertPlan:
    priority = priority_for(decision)
    if mode is AlertMode.OFF:
        return AlertPlan(False, priority, "alerts are off for this evaluation")
    if mode is AlertMode.ALWAYS:
        return AlertPlan(True, priority, "you asked about this listing")
    if decision is Decision.REJECTED:
        return AlertPlan(False, priority, "not a deal")
    if previous is None:
        return AlertPlan(True, priority, "first alert for this listing")
    if decision.rank > previous.decision.rank:
        return AlertPlan(True, priority, f"decision improved from {previous.decision.value}")
    if material_price_drop(previous.price, price, rules):
        return AlertPlan(True, priority, f"price dropped from {previous.price}")
    return AlertPlan(False, priority, "no material change since the last alert")


def previous_alert(
    session: Session, listing_id: int, *, exclude_evaluation_id: int
) -> PreviousAlert | None:
    row = session.execute(
        select(ListingEvaluation.decision, ListingEvaluation.price_at_evaluation)
        .join(Alert, Alert.evaluation_id == ListingEvaluation.id)
        .where(
            Alert.listing_id == listing_id,
            Alert.channel == CHANNEL,
            Alert.status == AlertStatus.SENT.value,
            Alert.evaluation_id != exclude_evaluation_id,
        )
        .order_by(Alert.sent_at.desc(), Alert.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    return PreviousAlert(decision=Decision(row[0]), price=row[1])


def open_alert(
    session: Session,
    evaluation: ListingEvaluation,
    *,
    mode: AlertMode,
    chat_id: int,
    rules: RealertRules,
) -> tuple[Alert | None, AlertPlan | None]:
    """The evaluation's alert row, locked for this transaction.

    Created (with the policy applied) the first time. Returns ``(None, None)`` if another worker
    holds the row: it is being sent right now.
    """
    alert = session.scalars(
        select(Alert)
        .where(Alert.evaluation_id == evaluation.id, Alert.channel == CHANNEL)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    ).first()
    if alert is not None:
        return alert, None
    plan = plan_alert(
        mode,
        Decision(evaluation.decision),
        evaluation.price_at_evaluation,
        previous_alert(session, evaluation.listing_id, exclude_evaluation_id=evaluation.id),
        rules,
    )
    new_id = session.execute(
        pg_insert(Alert)
        .values(
            evaluation_id=evaluation.id,
            listing_id=evaluation.listing_id,
            channel=CHANNEL,
            chat_id=chat_id,
            priority=plan.priority.value,
            status=(AlertStatus.PENDING if plan.send else AlertStatus.SUPPRESSED).value,
        )
        .on_conflict_do_nothing(index_elements=["evaluation_id", "channel"])
        .returning(Alert.id)
    ).scalar_one_or_none()
    if new_id is None:
        return None, None
    return session.get(Alert, new_id), plan


def record_decision(
    session: Session, alert_id: int, decision: UserDecision, *, actor: Actor, now: datetime
) -> Alert:
    alert = session.get(Alert, alert_id, with_for_update=True)
    if alert is None:
        raise NotFoundError(f"alert {alert_id} not found")
    before = {"user_decision": alert.user_decision}
    alert.user_decision = decision.value
    alert.decided_at = now
    alert.decided_by_user_id = actor.user_id
    audit.record(
        session, actor, action="alert.decision", entity_type="alert", entity_id=alert.id,
        before=before, after={"user_decision": decision.value},
    )  # fmt: skip
    return alert


# --------------------------------------------------------------------------- message view


def _reasons(decision: Decision, details: dict[str, Any]) -> tuple[str, ...]:
    kinds = {
        Decision.REJECTED: {"gate"},
        Decision.REVIEW: {"gate", "limit"},
        Decision.NORMAL: {"limit"},
        Decision.HIGH_PRIORITY: set(),
    }[decision]
    out = []
    for reason in details.get("reasons") or []:
        if isinstance(reason, dict) and reason.get("kind") in kinds and reason.get("detail"):
            detail = str(reason["detail"])
            out.append(detail[:1].upper() + detail[1:])
    return tuple(out)


def _headline(listing: Listing, product: Product | None, brand: Brand | None) -> str:
    if product is None or product.level == ProductLevel.BRAND_CATEGORY_GENERIC.value:
        return listing.title
    name = product.canonical_name
    if brand is not None and name.lower().startswith(brand.name.lower() + " "):
        name = name[len(brand.name) + 1 :]
    return name[:1].upper() + name[1:]


def build_alert_view(
    session: Session,
    evaluation: ListingEvaluation,
    *,
    now: datetime,
    base_currency: str = "GBP",
) -> AlertView:
    listing = session.get(Listing, evaluation.listing_id)
    if listing is None:
        raise NotFoundError(f"listing {evaluation.listing_id} not found")
    brand = session.get(Brand, evaluation.brand_id) if evaluation.brand_id else None
    product = session.get(Product, evaluation.product_id) if evaluation.product_id else None
    details = evaluation.details or {}
    auth = details.get("authenticity") or {}
    concerns = auth.get("concerns") or []
    decision = Decision(evaluation.decision)
    condition = listing.condition
    seen = (
        f"Listed {humanize_age(listing.listed_at, now)}"
        if listing.listed_at
        else f"Added {humanize_age(listing.first_seen_at, now)}"
    )
    return AlertView(
        decision=decision,
        listing_id=listing.id,
        headline=_headline(listing, product, brand),
        currency=evaluation.currency or listing.currency or base_currency,
        brand=brand.name if brand else None,
        size=listing.size_normalised,
        condition=Condition(condition).label if condition in set(Condition) else None,
        colour=listing.colour.capitalize() if listing.colour else None,
        price=evaluation.price_at_evaluation,
        max_buy=evaluation.max_purchase_price,
        expected=evaluation.expected_sale_price,
        quick=evaluation.quick_sale_price,
        optimistic=evaluation.optimistic_sale_price,
        comp_count=evaluation.comp_sample_size,
        comp_level=CompLevel(evaluation.comp_level) if evaluation.comp_level else None,
        estimate_confidence=evaluation.estimate_confidence,
        total_investment=evaluation.total_acquisition_cost,
        expected_profit=evaluation.expected_profit,
        roi=evaluation.expected_roi,
        median_days=evaluation.median_days_to_sale,
        liquidity=evaluation.liquidity_score,
        product_confidence=evaluation.match_confidence,
        auth_risk=evaluation.authenticity_risk_score,
        auth_level=auth.get("risk_level"),
        auth_confidence=evaluation.authenticity_confidence,
        auth_note=str(concerns[0]) if concerns else None,
        reasons=_reasons(decision, details),
        checks=tuple(str(c) for c in auth.get("recommended_checks") or []),
        url=listing.url,
        seen=seen,
    )


def latest_evaluation(session: Session, listing_id: int) -> ListingEvaluation | None:
    return session.scalars(
        select(ListingEvaluation)
        .where(ListingEvaluation.listing_id == listing_id)
        .order_by(ListingEvaluation.evaluated_at.desc(), ListingEvaluation.id.desc())
        .limit(1)
    ).first()


def latest_alert_for_listing(session: Session, listing_id: int) -> Alert | None:
    return session.scalars(
        select(Alert)
        .where(Alert.listing_id == listing_id, Alert.channel == CHANNEL)
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(1)
    ).first()
