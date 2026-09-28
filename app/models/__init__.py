"""SQLAlchemy ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.base import Base
from app.models.catalogue import (
    BotState,
    Brand,
    BrandAlias,
    Category,
    CategoryAlias,
    ConfigVersion,
    FxRate,
    Marketplace,
    Product,
    ProductAlias,
    TaskFailure,
)
from app.models.evaluation import AIRequest, Alert, ListingEvaluation
from app.models.inventory import InventoryEvent, InventoryItem, PredictionResult, Purchase, Resale
from app.models.market import MarketSale, MarketStatistic
from app.models.marketplace import (
    IngestionRun,
    Listing,
    ListingImage,
    ListingStatusHistory,
    PriceHistory,
    Seller,
)
from app.models.security import ApiKey, AuditLog, User

__all__ = [
    "AIRequest",
    "Alert",
    "ApiKey",
    "AuditLog",
    "Base",
    "BotState",
    "Brand",
    "BrandAlias",
    "Category",
    "CategoryAlias",
    "ConfigVersion",
    "FxRate",
    "IngestionRun",
    "InventoryEvent",
    "InventoryItem",
    "Listing",
    "ListingEvaluation",
    "ListingImage",
    "ListingStatusHistory",
    "MarketSale",
    "MarketStatistic",
    "Marketplace",
    "PredictionResult",
    "PriceHistory",
    "Product",
    "ProductAlias",
    "Purchase",
    "Resale",
    "Seller",
    "TaskFailure",
    "User",
]
