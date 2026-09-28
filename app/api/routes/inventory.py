"""Your stock: status changes, costs, sales."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.deps import PrincipalDep, SessionDep
from app.core.enums import InventoryStatus
from app.core.time import days_between, utcnow
from app.models import InventoryEvent, InventoryItem, PredictionResult
from app.schemas.inventory import (
    CancelIn,
    EventOut,
    InventoryDetailOut,
    InventoryItemOut,
    ItemUpdate,
    PredictionOut,
    ResaleIn,
    ResaleOut,
    ResaleUpdate,
    TransitionIn,
)
from app.services.config_service import ConfigService
from app.services.inventory import (
    cancel_resale,
    get_item,
    get_resale,
    record_resale,
    transition_item,
    update_item,
    update_resale,
)

router = APIRouter(tags=["inventory"])


def detail(session: SessionDep, item: InventoryItem) -> InventoryDetailOut:
    events = session.scalars(
        select(InventoryEvent)
        .where(InventoryEvent.inventory_item_id == item.id)
        .order_by(InventoryEvent.occurred_at, InventoryEvent.id)
    )
    prediction = session.scalar(
        select(PredictionResult).where(PredictionResult.inventory_item_id == item.id)
    )
    resale = item.resale
    purchased_at = item.purchase.purchased_at
    end = resale.sold_at if resale else utcnow()
    return InventoryDetailOut(
        item=InventoryItemOut.model_validate(item),
        purchased_at=purchased_at,
        days_held=max(days_between(purchased_at, end), 0),
        events=[EventOut.model_validate(e) for e in events],
        sale=ResaleOut.model_validate(resale) if resale else None,
        profit=resale.net_proceeds - item.total_cost_basis if resale else None,
        prediction=PredictionOut.model_validate(prediction) if prediction else None,
    )


@router.get("/inventory")
def list_inventory(
    principal: PrincipalDep,
    session: SessionDep,
    status: Annotated[list[InventoryStatus] | None, Query()] = None,
    brand_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    query = select(InventoryItem)
    if status:
        query = query.where(InventoryItem.status.in_([s.value for s in status]))
    if brand_id is not None:
        query = query.where(InventoryItem.brand_id == brand_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(InventoryItem.id.desc()).limit(limit).offset(offset))
    return {
        "items": [InventoryItemOut.model_validate(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/inventory/{item_id}", response_model=InventoryDetailOut)
def get_inventory_item(
    item_id: int, principal: PrincipalDep, session: SessionDep
) -> InventoryDetailOut:
    return detail(session, get_item(session, item_id))


@router.patch("/inventory/{item_id}", response_model=InventoryDetailOut)
def patch_inventory_item(
    item_id: int, body: ItemUpdate, principal: PrincipalDep, session: SessionDep
) -> InventoryDetailOut:
    """Add costs after buying (cleaning, repairs, other) or listing details."""
    item = update_item(
        session, item_id, actor=principal.actor, at=utcnow(),
        **body.model_dump(exclude_unset=True),
    )  # fmt: skip
    session.commit()
    return detail(session, item)


@router.post("/inventory/{item_id}/status", response_model=InventoryDetailOut)
def change_status(
    item_id: int, body: TransitionIn, principal: PrincipalDep, session: SessionDep
) -> InventoryDetailOut:
    """Move an item along: in_transit, received, needs_work, ready_to_list, listed, shipped,
    completed, returned (sent back to the seller for a refund) or written_off."""
    item = transition_item(
        session, item_id, body.status, at=body.at or utcnow(), actor=principal.actor,
        note=body.note, listed_price=body.listed_price, listing_channel=body.listing_channel,
        listing_url=body.listing_url, condition=body.condition,
    )  # fmt: skip
    session.commit()
    return detail(session, item)


@router.post("/inventory/{item_id}/sale", response_model=InventoryDetailOut, status_code=201)
def record_sale_route(
    item_id: int, body: ResaleIn, principal: PrincipalDep, session: SessionDep
) -> InventoryDetailOut:
    """You sold the item. It becomes market data and the purchase-time prediction is scored."""
    fees = ConfigService(session).bundle().fees
    record_resale(
        session, item_id, sale_price=body.sale_price, sold_at=body.sold_at or utcnow(),
        actor=principal.actor, fees=fees, channel=body.channel, currency=body.currency,
        selling_fees=body.selling_fees, outbound_shipping_cost=body.outbound_shipping_cost,
        shipping_charged_to_buyer=body.shipping_charged_to_buyer, refunds=body.refunds,
        other_selling_costs=body.other_selling_costs, notes=body.notes,
    )  # fmt: skip
    session.commit()
    return detail(session, get_item(session, item_id))


@router.patch("/resales/{resale_id}", response_model=ResaleOut)
def patch_resale(
    resale_id: int, body: ResaleUpdate, principal: PrincipalDep, session: SessionDep
) -> ResaleOut:
    """Correct a sale, or add what happened later (a refund, the payout date)."""
    resale = update_resale(
        session, resale_id, actor=principal.actor, at=utcnow(),
        changes=body.model_dump(exclude_unset=True),
    )  # fmt: skip
    session.commit()
    return ResaleOut.model_validate(resale)


@router.post("/resales/{resale_id}/cancel", response_model=InventoryDetailOut)
def cancel_resale_route(
    resale_id: int, body: CancelIn, principal: PrincipalDep, session: SessionDep
) -> InventoryDetailOut:
    """The sale fell through before completion: the item goes back on sale."""
    item = cancel_resale(session, resale_id, actor=principal.actor, at=utcnow(), reason=body.reason)
    session.commit()
    return detail(session, item)


@router.get("/resales/{resale_id}", response_model=ResaleOut)
def get_resale_route(resale_id: int, principal: PrincipalDep, session: SessionDep) -> ResaleOut:
    return ResaleOut.model_validate(get_resale(session, resale_id))
