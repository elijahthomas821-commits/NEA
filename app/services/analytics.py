"""Analytics: load your records and compute the metrics in :mod:`app.analysis.analytics`.

Only items in your base currency are counted (others are reported separately). CSV exports are
protected against spreadsheet formula injection: text that starts with ``= + - @`` (e.g. a
listing title) is prefixed with an apostrophe so a spreadsheet shows it instead of running it.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.analysis.analytics import (
    AccuracyReport,
    BreakdownRow,
    ItemRecord,
    Period,
    PredictionRecord,
    StockSnapshot,
    Summary,
    accuracy_report,
    breakdown,
    stock_snapshot,
    summarise,
)
from app.analysis.inventory.lifecycle import SOLD_STATES
from app.core.enums import InventoryStatus
from app.models import (
    AIRequest,
    Alert,
    Brand,
    Category,
    InventoryEvent,
    InventoryItem,
    Listing,
    ListingEvaluation,
    PredictionResult,
    Purchase,
    Resale,
)

EXPORT_KINDS = ("inventory", "sales", "evaluations")
MAX_EXPORT_ROWS = 50_000


def bounds(period: Period) -> tuple[datetime | None, datetime | None]:
    """UTC datetimes for a period of whole days (end exclusive)."""
    start = datetime.combine(period.start, time(0), tzinfo=UTC) if period.start else None
    end = (
        datetime.combine(period.end + timedelta(days=1), time(0), tzinfo=UTC)
        if period.end
        else None
    )
    return start, end


def _in_period[Q: Select](query: Q, column: Any, period: Period) -> Q:  # type: ignore[type-arg]
    start, end = bounds(period)
    if start is not None:
        query = query.where(column >= start)
    if end is not None:
        query = query.where(column < end)
    return query


# --------------------------------------------------------------------------- records


def item_records(session: Session, currency: str) -> tuple[list[ItemRecord], int]:
    """Every inventory item in ``currency``, and how many items are in other currencies."""
    exits = dict(
        session.execute(
            select(
                InventoryEvent.inventory_item_id,
                func.max(InventoryEvent.occurred_at),
            )
            .join(InventoryItem, InventoryItem.id == InventoryEvent.inventory_item_id)
            .where(
                InventoryEvent.to_status == InventoryItem.status,
                InventoryItem.status.in_(
                    [InventoryStatus.RETURNED.value, InventoryStatus.WRITTEN_OFF.value]
                ),
            )
            .group_by(InventoryEvent.inventory_item_id)
        ).all()
    )
    rows = session.execute(
        select(
            InventoryItem,
            Purchase.purchased_at,
            Resale,
            Brand.name,
            Category.name,
            ListingEvaluation.decision,
            PredictionResult.predicted_comp_level,
        )
        .join(Purchase, Purchase.id == InventoryItem.purchase_id)
        .outerjoin(Resale, Resale.inventory_item_id == InventoryItem.id)
        .outerjoin(Brand, Brand.id == InventoryItem.brand_id)
        .outerjoin(Category, Category.id == InventoryItem.category_id)
        .outerjoin(PredictionResult, PredictionResult.inventory_item_id == InventoryItem.id)
        .outerjoin(ListingEvaluation, ListingEvaluation.id == PredictionResult.evaluation_id)
        .order_by(InventoryItem.id)
    ).all()
    records: list[ItemRecord] = []
    other_currency = 0
    for item, purchased_at, resale, brand, category, decision, comp_level in rows:
        if item.currency != currency:
            other_currency += 1
            continue
        status = InventoryStatus(item.status)
        sold = resale is not None and status in SOLD_STATES
        records.append(
            ItemRecord(
                item_id=item.id,
                status=status,
                purchased_at=purchased_at,
                acquisition_cost=item.allocated_acquisition_cost,
                extra_costs=item.cleaning_cost + item.repair_cost + item.other_costs,
                exit_at=resale.sold_at if sold else exits.get(item.id),
                listed_at=item.listed_at,
                brand=brand,
                category=category,
                decision=decision,
                comp_level=comp_level,
                expected_resale_price=item.expected_resale_price,
                sold_at=resale.sold_at if sold else None,
                sale_price=resale.sale_price if sold else None,
                net_proceeds=resale.net_proceeds if sold else None,
            )
        )
    return records, other_currency


def prediction_records(session: Session, currency: str) -> list[PredictionRecord]:
    rows = session.scalars(
        select(PredictionResult)
        .where(PredictionResult.currency == currency)
        .order_by(PredictionResult.id)
    )
    return [
        PredictionRecord(
            comp_level=r.predicted_comp_level,
            from_price_guide=r.predicted_from_price_guide,
            predicted_quick=r.predicted_quick_sale,
            predicted_expected=r.predicted_expected_sale,
            predicted_optimistic=r.predicted_optimistic_sale,
            predicted_profit=r.predicted_profit,
            predicted_days=r.predicted_days_to_sale,
            actual_sale_price=r.actual_sale_price,
            actual_profit=r.actual_profit,
            actual_days=r.actual_days_to_sale,
            resolved_at=r.resolved_at,
        )
        for r in rows
    ]


# --------------------------------------------------------------------------- reports


class SummaryReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    currency: str
    summary: Summary
    stock: StockSnapshot
    items_in_other_currencies: int


def summary_report(
    session: Session, period: Period, *, currency: str, today: date
) -> SummaryReport:
    records, other = item_records(session, currency)
    return SummaryReport(
        currency=currency,
        summary=summarise(records, period, today=today),
        stock=stock_snapshot(records, today=today),
        items_in_other_currencies=other,
    )


def breakdown_report(
    session: Session, period: Period, by: str, *, currency: str
) -> list[BreakdownRow]:
    records, _ = item_records(session, currency)
    return breakdown(records, period, by)


def accuracy(session: Session, period: Period, *, currency: str) -> AccuracyReport:
    return accuracy_report(prediction_records(session, currency), period)


class Funnel(BaseModel):
    model_config = ConfigDict(frozen=True)

    listings_added: int
    evaluations: int
    evaluations_by_decision: dict[str, int]
    alerts_sent: int
    alerts_by_priority: dict[str, int]
    your_decisions: dict[str, int]
    purchases: int
    items_bought: int
    purchases_from_alerts: int
    buy_rate: Decimal | None  # purchases from alerts ÷ deal alerts sent (high/normal/review)
    ai_requests: int
    ai_cost_usd: Decimal


def _count(session: Session, query: Select) -> int:  # type: ignore[type-arg]
    return int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)


def _grouped(session: Session, query: Select[Any, int]) -> dict[str, int]:
    return {str(k): int(v) for k, v in session.execute(query).all() if k is not None}


def funnel(session: Session, period: Period) -> Funnel:
    listings = _count(session, _in_period(select(Listing.id), Listing.first_seen_at, period))
    by_decision = _grouped(
        session,
        _in_period(
            select(ListingEvaluation.decision, func.count()),
            ListingEvaluation.evaluated_at,
            period,
        ).group_by(ListingEvaluation.decision),
    )
    sent = _in_period(
        select(Alert.priority, func.count()).where(Alert.status == "sent"), Alert.sent_at, period
    ).group_by(Alert.priority)
    by_priority = _grouped(session, sent)
    decisions = _grouped(
        session,
        _in_period(select(Alert.user_decision, func.count()), Alert.decided_at, period).group_by(
            Alert.user_decision
        ),
    )
    purchases = _in_period(select(Purchase), Purchase.purchased_at, period).subquery()
    purchase_count = int(session.scalar(select(func.count()).select_from(purchases)) or 0)
    items_bought = int(
        session.scalar(select(func.coalesce(func.sum(purchases.c.item_count), 0))) or 0
    )
    from_alerts = int(
        session.scalar(
            select(func.count()).select_from(purchases).where(purchases.c.alert_id.is_not(None))
        )
        or 0
    )
    deal_alerts = sum(v for k, v in by_priority.items() if k != "info")
    ai = session.execute(
        _in_period(
            select(func.count(), func.coalesce(func.sum(AIRequest.cost_usd), 0)),
            AIRequest.created_at,
            period,
        )
    ).one()
    return Funnel(
        listings_added=listings,
        evaluations=sum(by_decision.values()),
        evaluations_by_decision=by_decision,
        alerts_sent=sum(by_priority.values()),
        alerts_by_priority=by_priority,
        your_decisions=decisions,
        purchases=purchase_count,
        items_bought=items_bought,
        purchases_from_alerts=from_alerts,
        buy_rate=(
            (Decimal(from_alerts) / deal_alerts).quantize(Decimal("0.0001"))
            if deal_alerts
            else None
        ),
        ai_requests=int(ai[0]),
        ai_cost_usd=Decimal(ai[1]),
    )


# --------------------------------------------------------------------------- CSV export

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: object) -> str:
    """A CSV cell that a spreadsheet will never evaluate as a formula."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | Decimal | float):
        return str(value)
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def to_csv(header: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_cell(v) for v in row])
    return buffer.getvalue()


INVENTORY_COLUMNS = [
    "item_id", "purchase_id", "listing_id", "title", "brand", "category", "size", "colour",
    "status", "currency", "purchased_at", "acquisition_cost", "cleaning_cost", "repair_cost",
    "other_costs", "cost_basis", "expected_resale_price", "expected_profit", "received_at",
    "listed_at", "listed_price", "sold_at", "sale_price", "net_proceeds", "profit",
]  # fmt: skip
SALES_COLUMNS = [
    "resale_id", "item_id", "title", "channel", "sold_at", "currency", "sale_price",
    "shipping_charged_to_buyer", "selling_fees", "outbound_shipping_cost", "refunds",
    "other_selling_costs", "net_proceeds", "cost_basis", "profit", "paid_out_at",
    "predicted_expected_sale", "price_error", "days_to_sale",
]  # fmt: skip
EVALUATION_COLUMNS = [
    "evaluation_id", "listing_id", "evaluated_at", "trigger", "title", "url", "decision",
    "reason_codes", "price", "currency", "expected_sale_price", "expected_profit", "expected_roi",
    "max_purchase_price", "comp_level", "comp_sample_size", "authenticity_risk_score",
    "pipeline_version",
]  # fmt: skip


def export_csv(session: Session, kind: str, period: Period) -> str:
    if kind == "inventory":
        return _export_inventory(session, period)
    if kind == "sales":
        return _export_sales(session, period)
    if kind == "evaluations":
        return _export_evaluations(session, period)
    raise ValueError(f"unknown export {kind!r}")


def _export_inventory(session: Session, period: Period) -> str:
    query = (
        _in_period(
            select(InventoryItem, Purchase.purchased_at, Resale, Brand.name, Category.name)
            .join(Purchase, Purchase.id == InventoryItem.purchase_id)
            .outerjoin(Resale, Resale.inventory_item_id == InventoryItem.id)
            .outerjoin(Brand, Brand.id == InventoryItem.brand_id)
            .outerjoin(Category, Category.id == InventoryItem.category_id),
            Purchase.purchased_at,
            period,
        )
        .order_by(InventoryItem.id)
        .limit(MAX_EXPORT_ROWS)
    )
    rows = []
    for item, purchased_at, resale, brand, category in session.execute(query).all():
        basis = item.total_cost_basis
        rows.append([
            item.id, item.purchase_id, item.listing_id, item.title, brand, category,
            item.size_normalised, item.colour, item.status, item.currency, purchased_at,
            item.allocated_acquisition_cost, item.cleaning_cost, item.repair_cost,
            item.other_costs, basis, item.expected_resale_price, item.expected_profit,
            item.received_at, item.listed_at, item.listed_price,
            resale.sold_at if resale else None, resale.sale_price if resale else None,
            resale.net_proceeds if resale else None,
            resale.net_proceeds - basis if resale else None,
        ])  # fmt: skip
    return to_csv(INVENTORY_COLUMNS, rows)


def _export_sales(session: Session, period: Period) -> str:
    query = (
        _in_period(
            select(Resale, InventoryItem, PredictionResult)
            .join(InventoryItem, InventoryItem.id == Resale.inventory_item_id)
            .outerjoin(PredictionResult, PredictionResult.inventory_item_id == InventoryItem.id),
            Resale.sold_at,
            period,
        )
        .order_by(Resale.sold_at, Resale.id)
        .limit(MAX_EXPORT_ROWS)
    )
    rows = []
    for resale, item, prediction in session.execute(query).all():
        basis = item.total_cost_basis
        rows.append([
            resale.id, item.id, item.title, resale.channel, resale.sold_at, resale.currency,
            resale.sale_price, resale.shipping_charged_to_buyer, resale.selling_fees,
            resale.outbound_shipping_cost, resale.refunds, resale.other_selling_costs,
            resale.net_proceeds, basis, resale.net_proceeds - basis, resale.paid_out_at,
            prediction.predicted_expected_sale if prediction else None,
            prediction.price_error if prediction else None,
            prediction.actual_days_to_sale if prediction else None,
        ])  # fmt: skip
    return to_csv(SALES_COLUMNS, rows)


def _export_evaluations(session: Session, period: Period) -> str:
    query = (
        _in_period(
            select(ListingEvaluation, Listing.title, Listing.url).join(
                Listing, Listing.id == ListingEvaluation.listing_id
            ),
            ListingEvaluation.evaluated_at,
            period,
        )
        .order_by(ListingEvaluation.evaluated_at, ListingEvaluation.id)
        .limit(MAX_EXPORT_ROWS)
    )
    rows = []
    for evaluation, title, url in session.execute(query).all():
        rows.append([
            evaluation.id, evaluation.listing_id, evaluation.evaluated_at, evaluation.trigger,
            title, url, evaluation.decision, " ".join(evaluation.reason_codes),
            evaluation.price_at_evaluation, evaluation.currency, evaluation.expected_sale_price,
            evaluation.expected_profit, evaluation.expected_roi, evaluation.max_purchase_price,
            evaluation.comp_level, evaluation.comp_sample_size,
            evaluation.authenticity_risk_score, evaluation.pipeline_version,
        ])  # fmt: skip
    return to_csv(EVALUATION_COLUMNS, rows)
