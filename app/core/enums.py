"""Domain enumerations shared by analysis, persistence and presentation.

Stored in the database as VARCHAR with CHECK constraints (see app.models), which keeps Alembic
migrations simple when values are added.
"""

from __future__ import annotations

from enum import StrEnum


class Condition(StrEnum):
    NEW_WITH_TAGS = "new_with_tags"
    NEW_WITHOUT_TAGS = "new_without_tags"
    VERY_GOOD = "very_good"
    GOOD = "good"
    SATISFACTORY = "satisfactory"

    @property
    def label(self) -> str:
        return _CONDITION_LABELS[self]


_CONDITION_LABELS = {
    Condition.NEW_WITH_TAGS: "New with tags",
    Condition.NEW_WITHOUT_TAGS: "New without tags",
    Condition.VERY_GOOD: "Very good",
    Condition.GOOD: "Good",
    Condition.SATISFACTORY: "Satisfactory",
}


class ListingStatus(StrEnum):
    ACTIVE = "active"
    RESERVED = "reserved"
    SOLD = "sold"
    REMOVED = "removed"
    UNKNOWN = "unknown"


class ProductLevel(StrEnum):
    MODEL = "model"
    PRODUCT_LINE = "product_line"
    BRAND_CATEGORY_GENERIC = "brand_category_generic"


class AliasType(StrEnum):
    NAME = "name"
    MODEL_CODE = "model_code"
    NICKNAME = "nickname"
    MISSPELLING = "misspelling"


class AliasSource(StrEnum):
    SEED = "seed"
    MANUAL = "manual"
    LEARNED = "learned"


class IdentificationMethod(StrEnum):
    RULES = "rules"
    AI = "ai"
    RULES_AI = "rules+ai"
    MISLABEL_AI = "mislabel_ai"
    MANUAL = "manual"


class SaleSource(StrEnum):
    OWN_SALE = "own_sale"
    MANUAL_ENTRY = "manual_entry"
    CSV_IMPORT = "csv_import"
    OBSERVED_SOLD_LISTING = "observed_sold_listing"
    LICENSED_API = "licensed_api"


class PriceType(StrEnum):
    FINAL_SALE_PRICE = "final_sale_price"
    LAST_ASKING_PRICE = "last_asking_price"


class CompLevel(StrEnum):
    """Comparable-sales fallback levels, most specific first."""

    L1 = "L1"  # product + size + condition + colour
    L2 = "L2"  # product + size + condition
    L3 = "L3"  # product + condition (size-adjusted)
    L4 = "L4"  # product (condition- and size-adjusted)
    L5 = "L5"  # brand + category + condition (size-adjusted)
    L6 = "L6"  # brand + category (condition- and size-adjusted)
    GUIDE = "GUIDE"  # operator price guide (not sales data)

    @property
    def rank(self) -> int:
        return _LEVEL_RANK[self]

    @property
    def description(self) -> str:
        return _LEVEL_DESCRIPTIONS[self]


_LEVEL_RANK = {level: i for i, level in enumerate(CompLevel, start=1)}
_LEVEL_DESCRIPTIONS = {
    CompLevel.L1: "product+size+condition+colour",
    CompLevel.L2: "product+size+condition",
    CompLevel.L3: "product+condition",
    CompLevel.L4: "product",
    CompLevel.L5: "brand+category+condition",
    CompLevel.L6: "brand+category",
    CompLevel.GUIDE: "your price guide",
}


class Decision(StrEnum):
    HIGH_PRIORITY = "high_priority"
    NORMAL = "normal"
    REVIEW = "review"
    REJECTED = "rejected"

    @property
    def rank(self) -> int:
        """Higher is better."""
        return _DECISION_RANK[self]


_DECISION_RANK = {
    Decision.REJECTED: 0,
    Decision.REVIEW: 1,
    Decision.NORMAL: 2,
    Decision.HIGH_PRIORITY: 3,
}


class AlertPriority(StrEnum):
    HIGH = "high"
    NORMAL = "normal"
    REVIEW = "review"
    INFO = "info"  # evaluation results for manual submissions that did not qualify


class AlertStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class AlertMode(StrEnum):
    """Whether an evaluation should produce a Telegram message."""

    ALWAYS = "always"  # you asked about this listing: always send the result
    DEALS = "deals"  # only worthwhile results, under the re-alert policy (bulk/automatic)
    OFF = "off"


class UserDecision(StrEnum):
    BUY = "buy"
    PASS = "pass"  # noqa: S105 - not a password
    REVIEW = "review"


class InventoryStatus(StrEnum):
    ORDERED = "ordered"
    IN_TRANSIT = "in_transit"
    RECEIVED = "received"
    NEEDS_WORK = "needs_work"
    READY_TO_LIST = "ready_to_list"
    LISTED = "listed"
    SOLD = "sold"
    SHIPPED = "shipped"
    COMPLETED = "completed"
    RETURNED = "returned"
    WRITTEN_OFF = "written_off"


class ConfigKind(StrEnum):
    DEAL_RULES = "deal_rules"
    FEES = "fees"
    CONDITIONS = "conditions"
    SIZES = "sizes"
    MARKET = "market"
    AUTHENTICITY = "authenticity"
    IDENTIFICATION = "identification"
    PRICE_GUIDE = "price_guide"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CheckResult(StrEnum):
    """Outcome of one authenticity checklist item inspected in photos."""

    OBSERVED = "observed"
    NOT_VISIBLE = "not_visible"
    CONCERN = "concern"


def values(enum_cls: type[StrEnum]) -> list[str]:
    return [member.value for member in enum_cls]
