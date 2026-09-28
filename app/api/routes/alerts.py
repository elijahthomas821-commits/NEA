"""Alerts and your BUY / PASS / REVIEW decisions (also available as Telegram buttons)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.deps import PrincipalDep, SessionDep
from app.core.enums import AlertPriority, AlertStatus, UserDecision
from app.core.time import utcnow
from app.models import Alert
from app.schemas.inventory import AlertOut, DecisionIn
from app.services.alerts import record_decision

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    principal: PrincipalDep,
    session: SessionDep,
    status: AlertStatus | None = None,
    priority: AlertPriority | None = None,
    decision: UserDecision | None = None,
    undecided: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    query = select(Alert)
    if status is not None:
        query = query.where(Alert.status == status.value)
    if priority is not None:
        query = query.where(Alert.priority == priority.value)
    if decision is not None:
        query = query.where(Alert.user_decision == decision.value)
    if undecided:
        query = query.where(Alert.user_decision.is_(None))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(
        query.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit).offset(offset)
    )
    return {
        "items": [AlertOut.model_validate(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/{alert_id}/decision", response_model=AlertOut)
def decide(
    alert_id: int, body: DecisionIn, principal: PrincipalDep, session: SessionDep
) -> AlertOut:
    """Record your decision. BUY records intent only: record the purchase after buying."""
    alert = record_decision(
        session, alert_id, body.decision, actor=principal.actor, now=utcnow(), note=body.note
    )
    session.commit()
    return AlertOut.model_validate(alert)
