"""Business analytics (see docs/analytics.md for every definition)."""

from __future__ import annotations

from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse

from app.analysis.analytics import AccuracyReport, BreakdownRow, Period
from app.api.deps import PrincipalDep, SessionDep, SettingsDep
from app.core.errors import ValidationFailedError
from app.core.time import utcnow
from app.services import analytics

router = APIRouter(prefix="/analytics", tags=["analytics"])

FromQuery = Annotated[date | None, Query(alias="from", description="first day (UTC), inclusive")]
ToQuery = Annotated[date | None, Query(alias="to", description="last day (UTC), inclusive")]


def _period(start: date | None, end: date | None) -> Period:
    if start and end and start > end:
        raise ValidationFailedError("'from' is after 'to'")
    return Period(start=start, end=end)


@router.get("/summary", response_model=analytics.SummaryReport)
def summary(
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    start: FromQuery = None,
    end: ToQuery = None,
) -> analytics.SummaryReport:
    """Profit and loss for the period, plus your stock today."""
    return analytics.summary_report(
        session, _period(start, end), currency=settings.base_currency, today=utcnow().date()
    )


@router.get("/breakdown", response_model=list[BreakdownRow])
def breakdown(
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    by: Literal["brand", "category", "month", "decision", "comp_level"] = "brand",
    start: FromQuery = None,
    end: ToQuery = None,
) -> list[BreakdownRow]:
    """Sales in the period grouped by brand, category, month, decision tier or comp level."""
    return analytics.breakdown_report(
        session, _period(start, end), by, currency=settings.base_currency
    )


@router.get("/predictions", response_model=AccuracyReport)
def predictions(
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    start: FromQuery = None,
    end: ToQuery = None,
) -> AccuracyReport:
    """How close the purchase-time predictions were to what items actually sold for."""
    return analytics.accuracy(session, _period(start, end), currency=settings.base_currency)


@router.get("/funnel", response_model=analytics.Funnel)
def funnel(
    principal: PrincipalDep, session: SessionDep, start: FromQuery = None, end: ToQuery = None
) -> analytics.Funnel:
    """Listings → evaluations → alerts → your decisions → purchases, and AI spend."""
    return analytics.funnel(session, _period(start, end))


@router.get("/export/{kind}.csv", response_class=PlainTextResponse)
def export(
    kind: Literal["inventory", "sales", "evaluations"],
    principal: PrincipalDep,
    session: SessionDep,
    start: FromQuery = None,
    end: ToQuery = None,
) -> PlainTextResponse:
    content = analytics.export_csv(session, kind, _period(start, end))
    return PlainTextResponse(
        content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{kind}.csv"'},
    )
