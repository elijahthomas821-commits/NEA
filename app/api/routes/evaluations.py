"""Evaluations: history per listing, full detail, and evaluate-now."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import select

from app.api.deps import DispatcherDep, PrincipalDep, SessionDep, SettingsDep
from app.core.enums import AlertMode
from app.core.errors import NotFoundError
from app.models import Listing, ListingEvaluation
from app.schemas.evaluations import EvaluationDetail, EvaluationSummary
from app.services.ai.factory import build_ai_service
from app.services.pipeline import build_context, evaluate_listing

router = APIRouter(tags=["evaluations"])


@router.get("/listings/{listing_id}/evaluations", response_model=list[EvaluationSummary])
def listing_evaluations(
    listing_id: int, principal: PrincipalDep, session: SessionDep
) -> list[EvaluationSummary]:
    if session.get(Listing, listing_id) is None:
        raise NotFoundError(f"listing {listing_id} not found")
    rows = session.scalars(
        select(ListingEvaluation)
        .where(ListingEvaluation.listing_id == listing_id)
        .order_by(ListingEvaluation.evaluated_at.desc(), ListingEvaluation.id.desc())
    )
    return [EvaluationSummary.model_validate(r) for r in rows]


@router.get("/evaluations/{evaluation_id}", response_model=EvaluationDetail)
def get_evaluation(
    evaluation_id: int, principal: PrincipalDep, session: SessionDep
) -> EvaluationDetail:
    row = session.get(ListingEvaluation, evaluation_id)
    if row is None:
        raise NotFoundError(f"evaluation {evaluation_id} not found")
    return EvaluationDetail.model_validate(row)


def _mode(notify: bool) -> AlertMode:
    return AlertMode.ALWAYS if notify else AlertMode.OFF


@router.post("/listings/{listing_id}/evaluate")
def evaluate_now(
    listing_id: int,
    request: Request,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: DispatcherDep,
    sync: bool = True,
    notify: bool = False,
) -> dict[str, Any]:
    """Re-evaluate a listing (e.g. after recording new comps or changing thresholds)."""
    listing = session.get(Listing, listing_id)
    if listing is None:
        raise NotFoundError(f"listing {listing_id} not found")
    correlation_id = getattr(request.state, "correlation_id", None)
    if not sync:
        dispatcher.evaluate_listing(
            listing_id, trigger="manual", alert=_mode(notify), correlation_id=correlation_id
        )
        return {"queued": True}
    ai = build_ai_service(settings, request.app.state.database)
    evaluation = evaluate_listing(
        session, listing, build_context(session, settings=settings, ai=ai), trigger="manual"
    )
    session.commit()
    if notify:
        dispatcher.send_alert(evaluation.id, alert=AlertMode.ALWAYS, correlation_id=correlation_id)
    return {
        "queued": False,
        "evaluation": EvaluationDetail.model_validate(evaluation).model_dump(mode="json"),
    }
