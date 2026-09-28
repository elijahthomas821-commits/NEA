"""The Anthropic provider, with the SDK client replaced by a stub (no network)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest

from app.services.ai.anthropic_provider import FALLBACK_BETA, AnthropicProvider
from app.services.ai.prompts import output_schema
from app.services.ai.provider import AIUnavailableError, estimate_cost_usd
from app.services.ai.schemas import (
    AIImage,
    AIListingAnalysis,
    AnalysisRequest,
    CatalogueOption,
    ChecklistOption,
)

REQUEST = AnalysisRequest(
    title="Navy overshirt with arm badge",
    brand_field="Unbranded",
    brands=[
        CatalogueOption(slug="stone-island", name="Stone Island"),
        CatalogueOption(slug="moncler", name="Moncler"),
    ],
    categories=[CatalogueOption(slug="jackets", name="Jackets")],
    checklists=[
        ChecklistOption(brand="stone-island", code="compass_badge", description="Compass badge")
    ],
    images=[AIImage(sha256="abc", media_type="image/jpeg", data=b"\xff\xd8fake")],
)

GOOD = {
    "brand": "unknown",
    "category": "jackets",
    "product_hint": "overshirt",
    "colour": "navy",
    "identification_confidence": 0.6,
    "identification_evidence": ["title says overshirt"],
    "photo_brand": "stone-island",
    "photo_brand_confidence": 0.85,
    "photo_brand_evidence": ["compass badge on left sleeve"],
    "checklist": [
        {"brand": "stone-island", "code": "compass_badge", "result": "observed", "note": "clear"}
    ],
    "photo_quality": "good",
    "concerns": [],
}
_REQ = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


class StubMessages:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _response(text: str | None, stop_reason: str = "end_turn") -> SimpleNamespace:
    content = [SimpleNamespace(type="thinking", thinking="")]
    if text is not None:
        content.append(SimpleNamespace(type="text", text=text))
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        model="claude-opus-5",
        usage=SimpleNamespace(input_tokens=3000, output_tokens=400),
    )


def _provider(result: Any, **kwargs: Any) -> tuple[AnthropicProvider, StubMessages]:
    stub = StubMessages(result)
    client = SimpleNamespace(beta=SimpleNamespace(messages=stub))
    provider = AnthropicProvider(
        api_key="sk-ant-test", model="claude-opus-5", timeout_seconds=5, client=client, **kwargs
    )
    return provider, stub


def test_successful_analysis_and_request_shape():
    provider, stub = _provider(_response(json.dumps(GOOD)))
    result = provider.analyse(REQUEST)
    assert result.output.photo_brand == "stone-island"
    assert (result.input_tokens, result.output_tokens) == (3000, 400)

    kwargs = stub.kwargs
    assert kwargs["model"] == "claude-opus-5"
    assert kwargs["betas"] == [FALLBACK_BETA]
    assert kwargs["fallbacks"] == "default"
    assert kwargs["output_config"]["effort"] == "low"
    schema = kwargs["output_config"]["format"]["schema"]
    assert schema["properties"]["brand"]["enum"] == ["moncler", "stone-island", "unknown"]
    content = kwargs["messages"][0]["content"]
    assert content[0]["type"] == "image"
    assert content[0]["source"]["type"] == "base64"
    assert content[-1]["type"] == "text"
    assert "Navy overshirt" in content[-1]["text"]


def test_fallbacks_can_be_disabled():
    provider, stub = _provider(_response(json.dumps(GOOD)), refusal_fallbacks=False)
    provider.analyse(REQUEST)
    assert "fallbacks" not in stub.kwargs
    assert "betas" not in stub.kwargs


@pytest.mark.parametrize(
    ("result", "status"),
    [
        (_response(None, stop_reason="refusal"), "error"),
        (_response(json.dumps(GOOD)[:40], stop_reason="max_tokens"), "invalid_response"),
        (_response("not json"), "invalid_response"),
        (_response(json.dumps({**GOOD, "identification_confidence": 1.7})), "invalid_response"),
        (_response(json.dumps({**GOOD, "estimated_price": 120})), "invalid_response"),
        (_response(None), "invalid_response"),
        (anthropic.APITimeoutError(request=_REQ), "timeout"),
        (anthropic.APIConnectionError(request=_REQ), "error"),
        (
            anthropic.InternalServerError(
                "overloaded", response=httpx2.Response(529, request=_REQ), body=None
            ),
            "error",
        ),
    ],
)
def test_failures_map_to_statuses(result, status):
    provider, _ = _provider(result)
    with pytest.raises(AIUnavailableError) as err:
        provider.analyse(REQUEST)
    assert err.value.status == status
    assert "sk-ant" not in err.value.message


def test_schema_and_output_model_have_no_money_fields():
    money_words = ("price", "value", "cost", "worth", "resale", "profit", "gbp", "£")
    fields = set(AIListingAnalysis.model_fields) | set(output_schema(REQUEST)["properties"])
    assert not [f for f in fields if any(w in f.lower() for w in money_words)]
    # Nor does the request carry any price.
    assert not [f for f in AnalysisRequest.model_fields if "price" in f]


def test_cost_estimate():
    assert str(estimate_cost_usd("claude-opus-5", 1_000_000, 0)) == "5.000000"
    assert str(estimate_cost_usd("claude-opus-5", 3000, 400)) == "0.025000"
    assert estimate_cost_usd("some-future-model", 1000, 1000) > 0
