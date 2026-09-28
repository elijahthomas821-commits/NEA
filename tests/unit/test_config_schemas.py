from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.config.loader import load_default_config, load_default_payload
from app.config.schemas import (
    DealRulesConfig,
    FeeRule,
    FeesConfig,
    MarketConfig,
    PriceGuideEntry,
    SizesConfig,
    dump_config,
    validate_config,
)
from app.core.enums import CompLevel, ConfigKind


@pytest.mark.parametrize("kind", list(ConfigKind))
def test_every_default_config_is_valid_and_round_trips(kind):
    model = load_default_config(kind)
    dumped = dump_config(model)
    assert validate_config(kind, dumped) == model


def test_unknown_keys_are_rejected():
    payload = load_default_payload(ConfigKind.DEAL_RULES)
    payload["min_proft"] = "10"  # typo
    with pytest.raises(ValidationError):
        DealRulesConfig.model_validate(payload)


def test_money_values_stay_exact():
    fees = load_default_config(ConfigKind.FEES)
    assert isinstance(fees, FeesConfig)
    assert fees.purchase_channels["vinted"].buyer_fee.fixed == Decimal("0.70")
    assert dump_config(fees)["purchase_channels"]["vinted"]["buyer_fee"]["fixed"] == "0.70"


def test_fee_rule_rejects_percent_and_tiers_together():
    with pytest.raises(ValidationError):
        FeeRule.model_validate({"percent": "0.1", "tiers": [{"percent": "0.1"}]})


def test_fee_rule_tiers_must_increase():
    with pytest.raises(ValidationError):
        FeeRule.model_validate(
            {"tiers": [{"up_to": "50", "percent": "0.1"}, {"up_to": "20", "percent": "0.05"}]}
        )
    with pytest.raises(ValidationError):
        FeeRule.model_validate(
            {"tiers": [{"up_to": None, "percent": "0.1"}, {"up_to": "20", "percent": "0.05"}]}
        )


def test_fees_default_channel_must_exist():
    payload = load_default_payload(ConfigKind.FEES)
    payload["default_selling_channel"] = "ebay"
    with pytest.raises(ValidationError):
        FeesConfig.model_validate(payload)


def test_market_levels_must_be_ordered():
    with pytest.raises(ValidationError):
        MarketConfig.model_validate({"levels": ["L3", "L1"]})
    with pytest.raises(ValidationError):
        MarketConfig.model_validate({"levels": ["L1", "GUIDE"]})
    assert MarketConfig.model_validate({"levels": ["L2", "L5"]}).levels == [
        CompLevel.L2,
        CompLevel.L5,
    ]


def test_ratio_bounds():
    with pytest.raises(ValidationError):
        DealRulesConfig.model_validate({"max_authenticity_risk": "1.5"})


def test_sizes_reject_unknown_letter():
    payload = load_default_payload(ConfigKind.SIZES)
    payload["numeric_systems"]["eu_it"]["60"] = "5XL"
    with pytest.raises(ValidationError):
        SizesConfig.model_validate(payload)


def test_price_guide_entry_ordering():
    with pytest.raises(ValidationError):
        PriceGuideEntry.model_validate(
            {"brand": "b", "category": "c", "low": "50", "typical": "40", "high": "60"}
        )


def test_conditions_require_every_grade():
    with pytest.raises(ValidationError):
        validate_config(ConfigKind.CONDITIONS, {"multipliers": {"good": "0.9"}})
