"""Comparable sales, market statistics, what-if estimates and FX rates."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, File, Query, Response, UploadFile
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from app.analysis.normalisation.colour import normalise_colour_field
from app.analysis.normalisation.condition import match_condition, match_condition_label
from app.analysis.normalisation.size import parse_size_value
from app.api.deps import PrincipalDep, SessionDep, SettingsDep
from app.api.uploads import read_upload
from app.collectors.base import RawSale
from app.core.enums import SaleSource
from app.core.errors import ValidationFailedError
from app.core.time import utcnow
from app.models import FxRate, MarketSale, MarketStatistic
from app.schemas.listings import IngestionRunOut
from app.schemas.market import EstimateIn, FxRateIn, SaleIn, SaleUpdate
from app.services import market_data
from app.services.catalogue import load_catalogue, resolve_brand, resolve_category
from app.services.config_service import ConfigService
from app.services.csv_import import SALES_COLUMNS, csv_template, import_sales_csv
from app.services.pricing import price_target

router = APIRouter(tags=["market"])


def _recorder(
    session: SessionDep, principal: PrincipalDep
) -> Callable[[RawSale], tuple[MarketSale, bool]]:
    bundle = ConfigService(session).bundle()
    catalogue = load_catalogue(session)

    def record(raw: RawSale) -> tuple[MarketSale, bool]:
        return market_data.record_sale(
            session,
            raw,
            catalogue=catalogue,
            identification=bundle.identification,
            sizes=bundle.sizes,
            actor=principal.actor,
        )

    return record


@router.post("/market/sales", status_code=201)
def add_sale(
    body: SaleIn,
    response: Response,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
) -> dict[str, Any]:
    """Record a comparable sale you researched. Duplicates are detected and not re-added."""
    raw = RawSale(
        source=SaleSource.MANUAL_ENTRY,
        currency=body.currency or settings.base_currency,
        **body.model_dump(exclude={"currency"}),
    )
    row, created = _recorder(session, principal)(raw)
    session.commit()
    response.status_code = 201 if created else 200
    return {"sale": market_data.sale_to_dict(row), "created": created}


@router.get("/market/sales")
def list_sales(
    principal: PrincipalDep,
    session: SessionDep,
    brand_id: int | None = None,
    category_id: int | None = None,
    product_id: int | None = None,
    include_excluded: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    query = select(MarketSale)
    for column, value in (
        (MarketSale.brand_id, brand_id),
        (MarketSale.category_id, category_id),
        (MarketSale.product_id, product_id),
    ):
        if value is not None:
            query = query.where(column == value)
    if not include_excluded:
        query = query.where(MarketSale.excluded.is_(False))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(
        query.order_by(MarketSale.sold_at.desc(), MarketSale.id.desc()).limit(limit).offset(offset)
    )
    return {
        "items": [market_data.sale_to_dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.patch("/market/sales/{sale_id}")
def update_sale(
    sale_id: int, body: SaleUpdate, principal: PrincipalDep, session: SessionDep
) -> dict[str, Any]:
    """Exclude a comp from pricing (e.g. a mistaken entry) or restore it."""
    row = market_data.set_excluded(
        session, sale_id, excluded=body.excluded, reason=body.reason, actor=principal.actor
    )
    session.commit()
    return market_data.sale_to_dict(row)


@router.get("/imports/templates/sales.csv", response_class=PlainTextResponse)
def sales_template(principal: PrincipalDep) -> str:
    return csv_template(SALES_COLUMNS)


@router.post("/imports/sales", response_model=IngestionRunOut, status_code=201)
def import_sales(
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    file: Annotated[UploadFile, File(description="UTF-8 CSV; see /imports/templates/sales.csv")],
) -> IngestionRunOut:
    content = read_upload(file, settings.max_upload_bytes)
    run = import_sales_csv(
        session,
        content,
        source=file.filename or "sales.csv",
        base_currency=settings.base_currency,
        now=utcnow(),
        record=_recorder(session, principal),
        user_id=principal.user.id,
    )
    session.commit()
    return IngestionRunOut.model_validate(run)


@router.post("/market/estimate")
def estimate(
    body: EstimateIn, principal: PrincipalDep, session: SessionDep, settings: SettingsDep
) -> dict[str, Any]:
    """What would this item resell for? Uses the same engine as listing evaluations."""
    bundle = ConfigService(session).bundle()
    catalogue = load_catalogue(session)
    brand = resolve_brand(catalogue, body.brand)
    category = resolve_category(catalogue, body.category)
    if brand is None or category is None:
        raise ValidationFailedError("unknown brand or category")
    raw = RawSale(
        source=SaleSource.MANUAL_ENTRY,
        brand=brand.slug,
        category=category.slug,
        product=body.product,
        title=body.title,
        sale_price=Decimal(1),
        currency=body.currency or settings.base_currency,
        sold_at=utcnow(),
    )
    product_id, match_confidence = market_data.resolve_product(
        session, raw, catalogue, brand.id, category.id, bundle.identification, bundle.sizes
    )
    condition = match_condition_label(body.condition) or (
        m.condition if (m := match_condition(body.condition, "field")) else None
    )
    size = parse_size_value(body.size, brand_slug=brand.slug, config=bundle.sizes)
    outcome = price_target(
        session,
        bundle,
        catalogue,
        brand_id=brand.id,
        category_id=category.id,
        product_id=product_id,
        size=size.normalised,
        colour=normalise_colour_field(body.colour),
        condition=condition,
        currency=raw.currency,
        match_confidence=match_confidence,
        as_of=utcnow(),
    )
    est = outcome.estimate
    return {
        "estimate": est.model_dump(mode="json") if est else None,
        "product_id": product_id,
        "levels_tried": [a.model_dump(mode="json") for a in outcome.market.attempts],
        "excluded": [e.model_dump(mode="json") for e in outcome.market.excluded],
        "comps_used": [
            {
                "sale_id": c.sale_id,
                "price": str(c.original_price),
                "adjusted": str(c.adjusted_price.quantize(c.original_price)),
                "weight": str(c.weight.quantize(c.match)),
            }
            for c in outcome.market.comps
        ],
        "message": None
        if est
        else "not enough sales data: record comps (POST /market/sales) or add a price guide entry",
    }


@router.get("/market/statistics")
def statistics(
    principal: PrincipalDep,
    session: SessionDep,
    brand_id: int | None = None,
    category_id: int | None = None,
) -> list[dict[str, Any]]:
    query = select(MarketStatistic)
    if brand_id is not None:
        query = query.where(MarketStatistic.brand_id == brand_id)
    if category_id is not None:
        query = query.where(MarketStatistic.category_id == category_id)
    return [
        {
            "scope_level": row.scope_level,
            "product_id": row.product_id,
            "brand_id": row.brand_id,
            "category_id": row.category_id,
            "currency": row.currency,
            "sample_size": row.sample_size,
            "effective_sample_size": row.effective_sample_size,
            "p10": row.p10,
            "p25": row.p25,
            "median": row.median,
            "p75": row.p75,
            "p90": row.p90,
            "median_days_to_sale": row.median_days_to_sale,
            "sales_last_30d": row.sales_last_30d,
            "sales_last_90d": row.sales_last_90d,
            "active_listings_observed": row.active_listings_observed,
            "computed_at": row.computed_at,
        }
        for row in session.scalars(query.order_by(MarketStatistic.id))
    ]


@router.post("/fx-rates", status_code=201)
def set_fx_rate(body: FxRateIn, principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    row = market_data.add_fx_rate(
        session,
        base=body.base,
        quote=body.quote,
        rate=body.rate,
        as_of=body.as_of,
        actor=principal.actor,
    )
    session.commit()
    return {"base": row.base, "quote": row.quote, "rate": row.rate, "as_of": row.as_of}


@router.get("/fx-rates")
def list_fx_rates(principal: PrincipalDep, session: SessionDep) -> list[dict[str, Any]]:
    rows = session.scalars(select(FxRate).order_by(FxRate.as_of.desc()).limit(200))
    return [{"base": r.base, "quote": r.quote, "rate": r.rate, "as_of": r.as_of} for r in rows]
