"""Prompt text and the output JSON schema for listing analysis."""

from __future__ import annotations

from typing import Any

from app.analysis.normalisation.colour import CANONICAL_COLOURS
from app.services.ai.schemas import AnalysisRequest

PROMPT_VERSION = "2026-09-28.1"

SYSTEM_PROMPT = """\
You help a second-hand clothing reseller identify items listed on marketplaces such as Vinted.
You look at the listing text and photos and report what you can actually see or read.

Rules:
- Choose brand and category only from the lists provided, or "unknown". Never invent one.
- Base the brand on evidence: brand names in the text, logos, badges, labels, hardware, or
  distinctive design details visible in the photos. Say what the evidence is.
- "photo_brand" is the brand whose marks you can see in the photos, judged from the photos
  alone (the seller may have left the brand out of the text).
- Do not estimate prices or values, and do not judge whether an item is authentic. For each
  checklist item, only report whether it is visible in the photos ("observed"), not visible
  ("not_visible"), or visible but looks inconsistent or questionable ("concern"), with a short
  note on what you see.
- Confidence values are between 0 and 1 and should reflect how clear the evidence is.
- Keep evidence notes short and factual.
"""


def build_user_text(request: AnalysisRequest) -> str:
    lines = ["Listing details (as written by the seller unless noted):"]
    lines.append(f"- Title: {request.title}")
    for label, value in (
        ("Brand field", request.brand_field),
        ("Category field", request.category_field),
        ("Size field", request.size_field),
        ("Condition field", request.condition_field),
        ("Description", request.description),
        ("Buyer's own notes", request.operator_notes),
    ):
        if value:
            lines.append(f"- {label}: {value[:1500]}")
    lines.append("")
    lines.append("Brands you may choose from (use the slug):")
    lines.extend(f"- {b.slug}: {b.name}" for b in request.brands)
    lines.append("")
    lines.append("Categories you may choose from (use the slug):")
    lines.extend(f"- {c.slug}: {c.name}" for c in request.categories)
    if request.checklists:
        lines.append("")
        lines.append(
            "Photo checklist - report every item for the brand you identify (or for "
            "photo_brand when the text names no brand):"
        )
        lines.extend(f"- [{c.brand}] {c.code}: {c.description}" for c in request.checklists)
    lines.append("")
    if request.images:
        lines.append(f"{len(request.images)} photo(s) of the item are attached above.")
    else:
        lines.append(
            "No photos are available: set photo_brand to unknown and photo_quality to none."
        )
    return "\n".join(lines)


def output_schema(request: AnalysisRequest) -> dict[str, Any]:
    """JSON schema for structured output, with catalogue-constrained enums."""
    brand_enum = sorted({b.slug for b in request.brands} | {"unknown"})
    category_enum = sorted({c.slug for c in request.categories} | {"unknown"})
    string_list = {"type": "array", "items": {"type": "string"}}
    return {
        "type": "object",
        "properties": {
            "brand": {"type": "string", "enum": brand_enum},
            "category": {"type": "string", "enum": category_enum},
            "product_hint": {"type": "string"},
            "colour": {"type": "string", "enum": [*CANONICAL_COLOURS, "unknown"]},
            "identification_confidence": {"type": "number"},
            "identification_evidence": string_list,
            "photo_brand": {"type": "string", "enum": brand_enum},
            "photo_brand_confidence": {"type": "number"},
            "photo_brand_evidence": string_list,
            "checklist": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "brand": {"type": "string"},
                        "code": {"type": "string"},
                        "result": {
                            "type": "string",
                            "enum": ["observed", "not_visible", "concern"],
                        },
                        "note": {"type": "string"},
                    },
                    "required": ["brand", "code", "result", "note"],
                    "additionalProperties": False,
                },
            },
            "photo_quality": {"type": "string", "enum": ["good", "fair", "poor", "none"]},
            "concerns": string_list,
        },
        "required": [
            "brand",
            "category",
            "product_hint",
            "colour",
            "identification_confidence",
            "identification_evidence",
            "photo_brand",
            "photo_brand_confidence",
            "photo_brand_evidence",
            "checklist",
            "photo_quality",
            "concerns",
        ],
        "additionalProperties": False,
    }
