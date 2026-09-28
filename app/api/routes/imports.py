"""CSV imports."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import PlainTextResponse

from app.api.deps import DispatcherDep, PrincipalDep, SessionDep, SettingsDep
from app.api.uploads import read_upload
from app.core.enums import AlertMode
from app.core.errors import NotFoundError
from app.core.time import utcnow
from app.models import IngestionRun
from app.schemas.listings import IngestionRunOut
from app.services.csv_import import LISTING_COLUMNS, csv_template, import_listings_csv

router = APIRouter(prefix="/imports", tags=["imports"])


@router.get("/templates/listings.csv", response_class=PlainTextResponse)
def listings_template(principal: PrincipalDep) -> str:
    return csv_template(LISTING_COLUMNS)


@router.post("/listings", response_model=IngestionRunOut, status_code=201)
def import_listings(
    request: Request,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: DispatcherDep,
    file: Annotated[UploadFile, File(description="UTF-8 CSV; see /imports/templates/listings.csv")],
    notify: bool = False,
) -> IngestionRunOut:
    content = read_upload(file, settings.max_upload_bytes)
    run, results = import_listings_csv(
        session,
        content,
        source=file.filename or "upload.csv",
        base_currency=settings.base_currency,
        now=utcnow(),
        user_id=principal.user.id,
    )
    session.commit()
    for result in results:
        if result.needs_evaluation:
            dispatcher.evaluate_listing(
                result.listing.id,
                trigger="ingest" if result.created else "manual",
                # Bulk imports only message you about listings worth a look.
                alert=AlertMode.DEALS if notify else AlertMode.OFF,
                correlation_id=getattr(request.state, "correlation_id", None),
            )
    return IngestionRunOut.model_validate(run)


@router.get("/{run_id}", response_model=IngestionRunOut)
def get_import(run_id: int, principal: PrincipalDep, session: SessionDep) -> IngestionRunOut:
    run = session.get(IngestionRun, run_id)
    if run is None:
        raise NotFoundError(f"import {run_id} not found")
    return IngestionRunOut.model_validate(run)
