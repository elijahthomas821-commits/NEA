from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy import func, select

from app.config.loader import load_default_payload
from app.core.enums import ConfigKind, ProductLevel
from app.core.errors import NotFoundError, ValidationFailedError
from app.models import AuditLog, Brand, Category, ConfigVersion, Product
from app.services.audit import Actor
from app.services.config_service import ConfigService
from app.services.seed import seed_reference_data

pytestmark = pytest.mark.integration


def test_seed_is_idempotent(db_session):
    report = seed_reference_data(db_session)
    assert report.created == {}
    assert report.warnings == []


def test_every_brand_has_generic_product_per_in_scope_category(db_session):
    brands = db_session.scalar(select(func.count(Brand.id)))
    in_scope = db_session.scalar(select(func.count(Category.id)).where(Category.in_scope))
    generics = db_session.scalar(
        select(func.count(Product.id)).where(
            Product.level == ProductLevel.BRAND_CATEGORY_GENERIC.value
        )
    )
    assert brands == 5
    assert in_scope == 3
    assert generics == brands * in_scope


def test_all_config_kinds_active(db_session):
    bundle = ConfigService(db_session).bundle()
    assert set(bundle.version_ids) == {k.value for k in ConfigKind}
    assert bundle.deal_rules.min_profit == Decimal("25.00")


class TestConfigVersions:
    def test_identical_payload_is_a_no_op(self, db_session):
        service = ConfigService(db_session)
        before = service.active_row(ConfigKind.DEAL_RULES)
        row, created = service.create_version(
            ConfigKind.DEAL_RULES,
            load_default_payload(ConfigKind.DEAL_RULES),
            actor=Actor.system("test"),
        )
        assert not created
        assert row.id == before.id

    def test_new_version_deactivates_old_and_is_audited(self, db_session):
        service = ConfigService(db_session)
        old = service.active_row(ConfigKind.DEAL_RULES)
        payload = load_default_payload(ConfigKind.DEAL_RULES)
        payload["min_profit"] = "30.00"
        row, created = service.create_version(
            ConfigKind.DEAL_RULES, payload, actor=Actor.system("test"), note="raise min profit"
        )
        assert created
        assert row.version == old.version + 1
        db_session.refresh(old)
        assert not old.is_active
        _, model = service.get_active(ConfigKind.DEAL_RULES)
        assert model.min_profit == Decimal("30.00")  # type: ignore[attr-defined]
        assert (
            db_session.scalar(select(AuditLog).where(AuditLog.entity_id == str(row.id))) is not None
        )

    def test_invalid_payload_rejected_with_details(self, db_session):
        with pytest.raises(ValidationFailedError) as err:
            ConfigService(db_session).create_version(
                ConfigKind.DEAL_RULES, {"min_profit": "-5"}, actor=Actor.system("test")
            )
        assert err.value.details["errors"]

    def test_rollback_to_previous_version(self, db_session):
        service = ConfigService(db_session)
        original = service.active_row(ConfigKind.DEAL_RULES)
        payload = load_default_payload(ConfigKind.DEAL_RULES)
        payload["min_profit"] = "99.00"
        service.create_version(ConfigKind.DEAL_RULES, payload, actor=Actor.system("test"))
        service.activate_version(ConfigKind.DEAL_RULES, original.version, actor=Actor.system("t"))
        assert service.active_row(ConfigKind.DEAL_RULES).id == original.id
        active_count = db_session.scalar(
            select(func.count(ConfigVersion.id)).where(
                ConfigVersion.kind == "deal_rules", ConfigVersion.is_active
            )
        )
        assert active_count == 1

    def test_bundle_for_versions_reproduces_old_config(self, db_session):
        service = ConfigService(db_session)
        old_bundle = service.bundle()
        payload = load_default_payload(ConfigKind.DEAL_RULES)
        payload["min_profit"] = "77.00"
        service.create_version(ConfigKind.DEAL_RULES, payload, actor=Actor.system("test"))
        rebuilt = service.bundle_for_versions(old_bundle.version_ids)
        assert rebuilt.deal_rules.min_profit == old_bundle.deal_rules.min_profit
        assert service.bundle().deal_rules.min_profit == Decimal("77.00")

    def test_unknown_version(self, db_session):
        with pytest.raises(NotFoundError):
            ConfigService(db_session).activate_version(
                ConfigKind.FEES, 999, actor=Actor.system("t")
            )
