"""Versioned business configuration stored in ``config_versions``."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, cast

from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config.schemas import (
    AuthenticityConfig,
    ConditionsConfig,
    DealRulesConfig,
    FeesConfig,
    IdentificationConfig,
    MarketConfig,
    PriceGuideConfig,
    SizesConfig,
    StrictModel,
    dump_config,
    validate_config,
)
from app.core.enums import ConfigKind
from app.core.errors import NotFoundError, ValidationFailedError
from app.models import ConfigVersion
from app.services import audit
from app.services.audit import Actor


@dataclass(frozen=True)
class ConfigBundle:
    """Every active configuration, plus the version IDs (stored on each evaluation)."""

    deal_rules: DealRulesConfig
    fees: FeesConfig
    conditions: ConditionsConfig
    sizes: SizesConfig
    market: MarketConfig
    authenticity: AuthenticityConfig
    identification: IdentificationConfig
    price_guide: PriceGuideConfig
    version_ids: dict[str, int]


def checksum_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate(kind: ConfigKind, payload: dict[str, Any]) -> StrictModel:
    try:
        return validate_config(kind, payload)
    except ValidationError as exc:
        errors = [
            {"loc": ".".join(str(p) for p in err["loc"]), "msg": err["msg"]}
            for err in exc.errors(include_url=False)
        ]
        raise ValidationFailedError(
            f"invalid {kind.value} configuration", details={"errors": errors}
        ) from exc


class ConfigService:
    def __init__(self, session: Session) -> None:
        self.session = session

    # ------------------------------------------------------------------ reading

    def active_row(self, kind: ConfigKind, name: str = "default") -> ConfigVersion:
        row = self.session.scalar(
            select(ConfigVersion).where(
                ConfigVersion.kind == kind.value,
                ConfigVersion.name == name,
                ConfigVersion.is_active.is_(True),
            )
        )
        if row is None:
            raise NotFoundError(f"no active '{kind.value}' configuration - run `resale seed` first")
        return row

    def get_active(self, kind: ConfigKind, name: str = "default") -> tuple[int, StrictModel]:
        row = self.active_row(kind, name)
        return row.id, _validate(kind, row.payload)

    def bundle(self) -> ConfigBundle:
        models: dict[str, StrictModel] = {}
        ids: dict[str, int] = {}
        for kind in ConfigKind:
            version_id, model = self.get_active(kind)
            models[kind.value] = model
            ids[kind.value] = version_id
        return self._make_bundle(models, ids)

    def bundle_for_versions(self, version_ids: dict[str, int]) -> ConfigBundle:
        """Rebuild the exact configuration an old evaluation used."""
        models: dict[str, StrictModel] = {}
        for kind in ConfigKind:
            version_id = version_ids.get(kind.value)
            if version_id is None:
                raise NotFoundError(f"evaluation has no {kind.value} version recorded")
            row = self.session.get(ConfigVersion, version_id)
            if row is None or row.kind != kind.value:
                raise NotFoundError(f"config version {version_id} not found")
            models[kind.value] = _validate(kind, row.payload)
        return self._make_bundle(models, dict(version_ids))

    @staticmethod
    def _make_bundle(models: dict[str, StrictModel], ids: dict[str, int]) -> ConfigBundle:
        return ConfigBundle(
            deal_rules=cast(DealRulesConfig, models["deal_rules"]),
            fees=cast(FeesConfig, models["fees"]),
            conditions=cast(ConditionsConfig, models["conditions"]),
            sizes=cast(SizesConfig, models["sizes"]),
            market=cast(MarketConfig, models["market"]),
            authenticity=cast(AuthenticityConfig, models["authenticity"]),
            identification=cast(IdentificationConfig, models["identification"]),
            price_guide=cast(PriceGuideConfig, models["price_guide"]),
            version_ids=ids,
        )

    def list_versions(self, kind: ConfigKind, name: str = "default") -> list[ConfigVersion]:
        return list(
            self.session.scalars(
                select(ConfigVersion)
                .where(ConfigVersion.kind == kind.value, ConfigVersion.name == name)
                .order_by(ConfigVersion.version.desc())
            )
        )

    # ------------------------------------------------------------------ writing

    def create_version(
        self,
        kind: ConfigKind,
        payload: dict[str, Any],
        *,
        actor: Actor,
        note: str | None = None,
        name: str = "default",
        activate: bool = True,
    ) -> tuple[ConfigVersion, bool]:
        """Validate and store a new version. Returns ``(row, created)``.

        If the payload is identical to the active version nothing is written.
        """
        model = _validate(kind, payload)
        normalised = dump_config(model)
        checksum = checksum_payload(normalised)

        current = self.session.scalar(
            select(ConfigVersion).where(
                ConfigVersion.kind == kind.value,
                ConfigVersion.name == name,
                ConfigVersion.is_active.is_(True),
            )
        )
        if current is not None and current.checksum == checksum:
            return current, False

        next_version = (
            self.session.scalar(
                select(func.max(ConfigVersion.version)).where(
                    ConfigVersion.kind == kind.value, ConfigVersion.name == name
                )
            )
            or 0
        ) + 1

        if activate and current is not None:
            current.is_active = False
            self.session.flush()

        row = ConfigVersion(
            kind=kind.value,
            name=name,
            version=next_version,
            payload=normalised,
            checksum=checksum,
            is_active=activate,
            note=note,
            created_by=actor.label,
        )
        self.session.add(row)
        self.session.flush()
        audit.record(
            self.session,
            actor,
            action="config.create_version",
            entity_type="config_version",
            entity_id=row.id,
            before={"version": current.version, "id": current.id} if current else None,
            after={"kind": kind.value, "version": next_version, "active": activate},
        )
        return row, True

    def activate_version(
        self, kind: ConfigKind, version: int, *, actor: Actor, name: str = "default"
    ) -> ConfigVersion:
        row = self.session.scalar(
            select(ConfigVersion).where(
                ConfigVersion.kind == kind.value,
                ConfigVersion.name == name,
                ConfigVersion.version == version,
            )
        )
        if row is None:
            raise NotFoundError(f"{kind.value} version {version} not found")
        _validate(kind, row.payload)  # never activate something that no longer validates
        self.session.execute(
            update(ConfigVersion)
            .where(
                ConfigVersion.kind == kind.value,
                ConfigVersion.name == name,
                ConfigVersion.is_active.is_(True),
            )
            .values(is_active=False)
        )
        self.session.flush()
        row.is_active = True
        self.session.flush()
        audit.record(
            self.session,
            actor,
            action="config.activate_version",
            entity_type="config_version",
            entity_id=row.id,
            after={"kind": kind.value, "version": version},
        )
        return row
