"""Evaluation API schemas."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict


class EvaluationSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    listing_id: int
    evaluated_at: datetime
    trigger: str
    decision: str
    reason_codes: list[str]
    price_at_evaluation: Decimal | None
    currency: str | None
    product_id: int | None
    identification_method: str | None
    identification_confidence: Decimal | None
    match_confidence: Decimal | None
    mislabel_flag: bool
    estimate_basis: str | None
    comp_level: str | None
    comp_sample_size: int
    quick_sale_price: Decimal | None
    expected_sale_price: Decimal | None
    optimistic_sale_price: Decimal | None
    estimate_confidence: Decimal | None
    median_days_to_sale: Decimal | None
    liquidity_score: Decimal | None
    total_acquisition_cost: Decimal | None
    expected_profit: Decimal | None
    expected_roi: Decimal | None
    max_purchase_price: Decimal | None
    authenticity_risk_score: Decimal | None
    authenticity_confidence: Decimal | None
    ai_used: bool


class EvaluationDetail(EvaluationSummary):
    pipeline_version: str
    config_version_ids: dict[str, Any]
    details: dict[str, Any]
