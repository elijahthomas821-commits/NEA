"""The AI provider interface, its result type, errors and cost estimation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Literal, Protocol

from app.services.ai.schemas import AIListingAnalysis, AnalysisRequest

FailureStatus = Literal["error", "timeout", "invalid_response"]

# USD per million tokens (input, output), first-party API list prices. Used for budget
# tracking only; unknown models fall back to the configured default rates.
MODEL_PRICES_PER_MTOK: dict[str, tuple[Decimal, Decimal]] = {
    "claude-fable-5-1": (Decimal("10"), Decimal("50")),
    "claude-opus-5-5": (Decimal("4"), Decimal("20")),
    "claude-opus-5": (Decimal("5"), Decimal("25")),
    "claude-opus-4-8": (Decimal("5"), Decimal("25")),
    "claude-sonnet-5": (Decimal("2"), Decimal("10")),
    "claude-sonnet-4-6": (Decimal("3"), Decimal("15")),
    "claude-haiku-4-5": (Decimal("1"), Decimal("5")),
}
DEFAULT_PRICES = (Decimal("5"), Decimal("25"))
MILLION = Decimal(1_000_000)


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> Decimal:
    price_in, price_out = MODEL_PRICES_PER_MTOK.get(model, DEFAULT_PRICES)
    cost = (Decimal(input_tokens) * price_in + Decimal(output_tokens) * price_out) / MILLION
    return cost.quantize(Decimal("0.000001"))


@dataclass(frozen=True)
class ProviderResult:
    output: AIListingAnalysis
    input_tokens: int
    output_tokens: int
    model: str


class AIUnavailableError(Exception):
    """The provider could not produce a valid analysis (never contains secrets)."""

    def __init__(self, status: FailureStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class AIProvider(Protocol):
    name: str
    model: str

    def analyse(self, request: AnalysisRequest) -> ProviderResult: ...
