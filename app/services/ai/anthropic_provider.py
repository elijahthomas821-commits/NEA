"""Claude (Anthropic API) implementation of :class:`AIProvider`.

One request per analysis: listing photos as base64 images plus the listing text, with the
response constrained to a JSON schema (``output_config.format``) and then validated again by
our own strict Pydantic model. Low effort keeps this extraction task cheap. Server-side
refusal fallbacks are enabled by default (``ai_refusal_fallbacks``) so a policy decline on the
primary model is retried on a substitute model within the same call.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import anthropic
from pydantic import ValidationError

from app.services.ai.prompts import SYSTEM_PROMPT, build_user_text, output_schema
from app.services.ai.provider import AIUnavailableError, ProviderResult
from app.services.ai.schemas import AIListingAnalysis, AnalysisRequest

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        effort: str = "low",
        max_tokens: int = 4000,
        refusal_fallbacks: bool = True,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.refusal_fallbacks = refusal_fallbacks
        self._client = client or anthropic.Anthropic(
            api_key=api_key, timeout=timeout_seconds, max_retries=2
        )

    def _content(self, request: AnalysisRequest) -> list[dict[str, Any]]:
        blocks: list[dict[str, Any]] = [
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": image.media_type,
                    "data": base64.standard_b64encode(image.data).decode("ascii"),
                },
            }
            for image in request.images
        ]
        blocks.append({"type": "text", "text": build_user_text(request)})
        return blocks

    def analyse(self, request: AnalysisRequest) -> ProviderResult:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": SYSTEM_PROMPT,
            "output_config": {
                "effort": self.effort,
                "format": {"type": "json_schema", "schema": output_schema(request)},
            },
            "messages": [{"role": "user", "content": self._content(request)}],
        }
        if self.refusal_fallbacks:
            kwargs["betas"] = [FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        try:
            response = self._client.beta.messages.create(**kwargs)
        except anthropic.APITimeoutError as exc:
            raise AIUnavailableError("timeout", "AI request timed out") from exc
        except anthropic.RateLimitError as exc:
            raise AIUnavailableError("error", "AI provider rate limit") from exc
        except anthropic.APIStatusError as exc:
            raise AIUnavailableError("error", f"AI provider error {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:
            raise AIUnavailableError("error", "could not reach the AI provider") from exc

        if response.stop_reason == "refusal":
            raise AIUnavailableError("error", "the model declined to analyse this listing")
        if response.stop_reason == "max_tokens":
            raise AIUnavailableError("invalid_response", "AI response was cut off")
        text = next((block.text for block in response.content if block.type == "text"), None)
        if not text:
            raise AIUnavailableError("invalid_response", "AI response had no text")
        try:
            output = AIListingAnalysis.model_validate(json.loads(text))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise AIUnavailableError("invalid_response", "AI response failed validation") from exc
        usage = response.usage
        return ProviderResult(
            output=output,
            input_tokens=int(usage.input_tokens or 0)
            + int(getattr(usage, "cache_read_input_tokens", 0) or 0)
            + int(getattr(usage, "cache_creation_input_tokens", 0) or 0),
            output_tokens=int(usage.output_tokens or 0),
            model=str(response.model),
        )
