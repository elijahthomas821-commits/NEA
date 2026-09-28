"""Evaluations, alerts and the AI request audit trail."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AlertPriority,
    AlertStatus,
    CompLevel,
    Decision,
    IdentificationMethod,
    UserDecision,
)
from app.models.base import (
    Base,
    Money,
    Ratio,
    Score,
    created_at,
    currency_check,
    enum_check,
    non_negative,
    pk,
    score_check,
    updated_at,
    values_check,
)

EVALUATION_TRIGGERS = ["ingest", "manual", "price_change", "config_change", "backfill"]
ESTIMATE_BASES = ["comps", "price_guide"]
AI_STATUSES = ["ok", "error", "timeout", "invalid_response", "budget_exceeded"]


class ListingEvaluation(Base):
    """A complete, reproducible snapshot of one evaluation of one listing."""

    __tablename__ = "listing_evaluations"
    __table_args__ = (
        enum_check("decision", Decision),
        enum_check("identification_method", IdentificationMethod, nullable=True),
        enum_check("comp_level", CompLevel, nullable=True),
        values_check("trigger", EVALUATION_TRIGGERS),
        values_check("estimate_basis", ESTIMATE_BASES, nullable=True),
        currency_check(),
        score_check("identification_confidence"),
        score_check("match_confidence"),
        score_check("estimate_confidence"),
        score_check("liquidity_score"),
        score_check("authenticity_risk_score"),
        score_check("authenticity_confidence"),
        non_negative("max_purchase_price"),
        Index("ix_listing_evaluations_listing_evaluated", "listing_id", text("evaluated_at DESC")),
        Index("ix_listing_evaluations_decision_evaluated", "decision", text("evaluated_at DESC")),
    )

    id: Mapped[int] = pk()
    listing_id: Mapped[int] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"))
    evaluated_at: Mapped[datetime] = mapped_column()
    trigger: Mapped[str] = mapped_column(String(20), server_default=text("'ingest'"))
    pipeline_version: Mapped[str] = mapped_column(String(20))
    config_version_ids: Mapped[dict[str, Any]] = mapped_column(JSONB)

    price_at_evaluation: Mapped[Decimal | None] = mapped_column(Money)
    currency: Mapped[str | None] = mapped_column(String(3))

    brand_id: Mapped[int | None] = mapped_column(ForeignKey("brands.id", ondelete="SET NULL"))
    category_id: Mapped[int | None] = mapped_column(
        ForeignKey("categories.id", ondelete="SET NULL")
    )
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id", ondelete="SET NULL"))
    identification_method: Mapped[str | None] = mapped_column(String(20))
    identification_confidence: Mapped[Decimal | None] = mapped_column(Score)
    match_confidence: Mapped[Decimal | None] = mapped_column(Score)
    mislabel_flag: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))

    estimate_basis: Mapped[str | None] = mapped_column(String(16))
    comp_level: Mapped[str | None] = mapped_column(String(8))
    comp_sample_size: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    comp_effective_sample_size: Mapped[Decimal] = mapped_column(
        Numeric(10, 2), server_default=text("0")
    )
    quick_sale_price: Mapped[Decimal | None] = mapped_column(Money)
    expected_sale_price: Mapped[Decimal | None] = mapped_column(Money)
    optimistic_sale_price: Mapped[Decimal | None] = mapped_column(Money)
    estimate_confidence: Mapped[Decimal | None] = mapped_column(Score)

    median_days_to_sale: Mapped[Decimal | None] = mapped_column(Numeric(8, 1))
    liquidity_score: Mapped[Decimal | None] = mapped_column(Score)

    total_acquisition_cost: Mapped[Decimal | None] = mapped_column(Money)
    expected_selling_costs: Mapped[Decimal | None] = mapped_column(Money)
    expected_profit: Mapped[Decimal | None] = mapped_column(Money)  # may be negative
    expected_roi: Mapped[Decimal | None] = mapped_column(Ratio)  # may be negative
    max_purchase_price: Mapped[Decimal | None] = mapped_column(Money)

    authenticity_risk_score: Mapped[Decimal | None] = mapped_column(Score)
    authenticity_confidence: Mapped[Decimal | None] = mapped_column(Score)

    decision: Mapped[str] = mapped_column(String(16))
    reason_codes: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), server_default=text("'{}'::varchar[]")
    )
    # Every cost line, comp IDs and weights, identification evidence, signals.
    details: Mapped[dict[str, Any]] = mapped_column(JSONB)
    ai_used: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    ai_cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 6), server_default=text("0"))
    created_at: Mapped[datetime] = created_at()


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        # One alert per evaluation per channel: retries can never double-send.
        UniqueConstraint("evaluation_id", "channel"),
        values_check("channel", ["telegram"]),
        enum_check("priority", AlertPriority),
        enum_check("status", AlertStatus),
        enum_check("user_decision", UserDecision, nullable=True),
        non_negative("attempts"),
    )

    id: Mapped[int] = pk()
    evaluation_id: Mapped[int] = mapped_column(
        ForeignKey("listing_evaluations.id", ondelete="CASCADE")
    )
    listing_id: Mapped[int] = mapped_column(
        ForeignKey("listings.id", ondelete="CASCADE"), index=True
    )
    channel: Mapped[str] = mapped_column(String(16), server_default=text("'telegram'"))
    chat_id: Mapped[int | None] = mapped_column(BigInteger)
    external_message_id: Mapped[int | None] = mapped_column(BigInteger)
    priority: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), server_default=text("'pending'"), index=True)
    attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(String(500))
    sent_at: Mapped[datetime | None] = mapped_column()
    user_decision: Mapped[str | None] = mapped_column(String(16))
    decided_at: Mapped[datetime | None] = mapped_column()
    decided_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    decision_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    evaluation: Mapped[ListingEvaluation] = relationship()


class AIRequest(Base):
    """Every AI call: cost/budget tracking, audit, and the response cache (by input hash)."""

    __tablename__ = "ai_requests"
    __table_args__ = (
        values_check("status", AI_STATUSES),
        non_negative("input_tokens"),
        non_negative("output_tokens"),
        non_negative("cost_usd"),
        Index("ix_ai_requests_hash_purpose", "input_hash", "purpose"),
    )

    id: Mapped[int] = pk()
    purpose: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(64))
    input_hash: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    input_tokens: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    output_tokens: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), server_default=text("0"))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    # Only schema-validated results are stored (never raw model text).
    response: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(String(500))
    listing_id: Mapped[int | None] = mapped_column(ForeignKey("listings.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at()
