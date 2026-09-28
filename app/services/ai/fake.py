"""Deterministic AI provider for tests and offline demos."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal

from app.services.ai.provider import AIUnavailableError, ProviderResult
from app.services.ai.schemas import AIListingAnalysis, AnalysisRequest


@dataclass
class FakeProvider:
    """Returns ``responder(request)``; raises queued errors first."""

    responder: Callable[[AnalysisRequest], AIListingAnalysis]
    name: str = "fake"
    model: str = "fake-model"
    input_tokens: int = 1000
    output_tokens: int = 200
    errors: list[AIUnavailableError] = field(default_factory=list)
    calls: list[AnalysisRequest] = field(default_factory=list)

    def analyse(self, request: AnalysisRequest) -> ProviderResult:
        self.calls.append(request)
        if self.errors:
            raise self.errors.pop(0)
        return ProviderResult(
            output=self.responder(request),
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            model=self.model,
        )


def unknown_analysis(_: AnalysisRequest) -> AIListingAnalysis:
    return AIListingAnalysis(
        brand="unknown",
        category="unknown",
        identification_confidence=Decimal(0),
        photo_quality="none",
    )
