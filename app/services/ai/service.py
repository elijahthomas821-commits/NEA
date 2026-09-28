"""AI orchestration: budget guard, response cache, audit trail and catalogue validation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from io import BytesIO
from typing import Literal

from PIL import Image, ImageOps
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.identification.ai_merge import AIIdentityEvidence
from app.analysis.normalisation.colour import CANONICAL_COLOURS
from app.core.logging import get_logger
from app.core.time import Clock, SystemClock
from app.models import AIRequest
from app.services.ai.prompts import PROMPT_VERSION
from app.services.ai.provider import AIProvider, AIUnavailableError, estimate_cost_usd
from app.services.ai.schemas import AIChecklistItem, AIImage, AIListingAnalysis, AnalysisRequest

log = get_logger(__name__)

PURPOSE = "listing_analysis"
MAX_IMAGE_SIDE = 1024

OutcomeStatus = Literal[
    "ok", "cached", "disabled", "budget_exceeded", "error", "timeout", "invalid_response"
]


@dataclass(frozen=True)
class AIOutcome:
    status: OutcomeStatus
    analysis: AIListingAnalysis | None = None
    cost_usd: Decimal = Decimal(0)
    request_id: int | None = None
    detail: str | None = None

    @property
    def usable(self) -> bool:
        return self.analysis is not None


def prepare_image(data: bytes) -> tuple[bytes, str]:
    """Downscale to at most 1024 px on the long side and re-encode as JPEG (cost control)."""
    with Image.open(BytesIO(data)) as source:
        image = ImageOps.exif_transpose(source) or source
        image = image.convert("RGB")
        image.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
        buffer = BytesIO()
        image.save(buffer, format="JPEG", quality=85)
    return buffer.getvalue(), "image/jpeg"


def request_hash(request: AnalysisRequest, model: str) -> str:
    payload = {"prompt": PROMPT_VERSION, "model": model, "request": request.cache_key_payload()}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sanitise_analysis(analysis: AIListingAnalysis, request: AnalysisRequest) -> AIListingAnalysis:
    """Drop anything outside the catalogue / checklist we offered (defence in depth)."""
    brands = {b.slug for b in request.brands}
    categories = {c.slug for c in request.categories}
    offered = {(c.brand, c.code) for c in request.checklists}
    checklist: list[AIChecklistItem] = [
        item for item in analysis.checklist if (item.brand, item.code) in offered
    ]
    return analysis.model_copy(
        update={
            "brand": analysis.brand if analysis.brand in brands else "unknown",
            "category": analysis.category if analysis.category in categories else "unknown",
            "photo_brand": analysis.photo_brand if analysis.photo_brand in brands else "unknown",
            "colour": analysis.colour if analysis.colour in CANONICAL_COLOURS else "unknown",
            "checklist": checklist,
        }
    )


def to_identity_evidence(analysis: AIListingAnalysis) -> AIIdentityEvidence:
    def known(value: str) -> str | None:
        return None if value == "unknown" else value

    return AIIdentityEvidence(
        brand_slug=known(analysis.brand),
        category_slug=known(analysis.category),
        colour=known(analysis.colour),
        product_hint=analysis.product_hint or None,
        confidence=analysis.identification_confidence,
        evidence=list(analysis.identification_evidence),
        photo_brand_slug=known(analysis.photo_brand),
        photo_brand_confidence=analysis.photo_brand_confidence,
        photo_brand_evidence=list(analysis.photo_brand_evidence),
    )


def month_start(now: datetime) -> datetime:
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def day_start(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


class AIService:
    def __init__(
        self,
        provider: AIProvider | None,
        *,
        session_scope: Callable[[], AbstractContextManager[Session]],
        daily_budget_usd: Decimal,
        monthly_budget_usd: Decimal,
        clock: Clock | None = None,
    ) -> None:
        self.provider = provider
        self._session_scope = session_scope
        self.daily_budget_usd = daily_budget_usd
        self.monthly_budget_usd = monthly_budget_usd
        self.clock = clock or SystemClock()

    @property
    def enabled(self) -> bool:
        return self.provider is not None

    def spend(self, session: Session) -> tuple[Decimal, Decimal]:
        """(spent today, spent this month), UTC."""
        now = self.clock.now()
        today = session.scalar(
            select(func.coalesce(func.sum(AIRequest.cost_usd), 0)).where(
                AIRequest.created_at >= day_start(now)
            )
        )
        month = session.scalar(
            select(func.coalesce(func.sum(AIRequest.cost_usd), 0)).where(
                AIRequest.created_at >= month_start(now)
            )
        )
        return Decimal(today or 0), Decimal(month or 0)

    def _record(self, **fields: object) -> int:
        with self._session_scope() as session:
            row = AIRequest(purpose=PURPOSE, prompt_version=PROMPT_VERSION, **fields)
            session.add(row)
            session.flush()
            return row.id

    def analyse(self, request: AnalysisRequest, *, listing_id: int | None) -> AIOutcome:
        if self.provider is None:
            return AIOutcome(status="disabled")
        provider = self.provider
        digest = request_hash(request, provider.model)

        with self._session_scope() as session:
            cached = session.execute(
                select(AIRequest.id, AIRequest.response)
                .where(
                    AIRequest.input_hash == digest,
                    AIRequest.purpose == PURPOSE,
                    AIRequest.status == "ok",
                    AIRequest.response.is_not(None),
                )
                .order_by(AIRequest.id.desc())
                .limit(1)
            ).first()
            spent_today, spent_month = self.spend(session)
        if cached is not None:
            try:
                analysis = AIListingAnalysis.model_validate(cached[1])
                return AIOutcome(status="cached", analysis=analysis, request_id=cached[0])
            except ValidationError:
                log.warning("ai_cache_entry_invalid", request_id=cached[0])

        if spent_today >= self.daily_budget_usd or spent_month >= self.monthly_budget_usd:
            request_id = self._record(
                provider=provider.name,
                model=provider.model,
                input_hash=digest,
                status="budget_exceeded",
                listing_id=listing_id,
            )
            log.info("ai_budget_exceeded", today=str(spent_today), month=str(spent_month))
            return AIOutcome(
                status="budget_exceeded", request_id=request_id, detail="AI budget reached"
            )

        started = self.clock.now()
        try:
            result = provider.analyse(request)
        except AIUnavailableError as exc:
            request_id = self._record(
                provider=provider.name,
                model=provider.model,
                input_hash=digest,
                status=exc.status,
                error=exc.message[:500],
                listing_id=listing_id,
            )
            log.warning("ai_unavailable", status=exc.status, detail=exc.message)
            return AIOutcome(status=exc.status, request_id=request_id, detail=exc.message)

        latency_ms = int((self.clock.now() - started).total_seconds() * 1000)
        analysis = sanitise_analysis(result.output, request)
        cost = estimate_cost_usd(result.model, result.input_tokens, result.output_tokens)
        request_id = self._record(
            provider=provider.name,
            model=result.model,
            input_hash=digest,
            status="ok",
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_usd=cost,
            latency_ms=max(latency_ms, 0),
            response=analysis.model_dump(mode="json"),
            listing_id=listing_id,
        )
        return AIOutcome(status="ok", analysis=analysis, cost_usd=cost, request_id=request_id)


def build_images(items: list[tuple[str, bytes]]) -> list[AIImage]:
    """(sha256, raw bytes) → prepared images for the provider."""
    images: list[AIImage] = []
    for sha, data in items:
        try:
            prepared, media_type = prepare_image(data)
        except (OSError, ValueError):
            log.warning("ai_image_prepare_failed", sha256=sha)
            continue
        images.append(AIImage(sha256=sha, media_type=media_type, data=prepared))
    return images
