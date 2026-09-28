"""Loading of the YAML defaults shipped in ``app/config/defaults``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.config.schemas import StrictModel, validate_config
from app.core.enums import ConfigKind

DEFAULTS_DIR = Path(__file__).parent / "defaults"


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_default_payload(kind: ConfigKind) -> dict[str, Any]:
    data = load_yaml(DEFAULTS_DIR / f"{kind.value}.yaml")
    if not isinstance(data, dict):
        raise ValueError(f"{kind.value}.yaml must contain a mapping")
    return data


def load_default_config(kind: ConfigKind) -> StrictModel:
    return validate_config(kind, load_default_payload(kind))


def load_catalogue_file(name: str) -> dict[str, Any]:
    data = load_yaml(DEFAULTS_DIR / f"{name}.yaml")
    if not isinstance(data, dict):
        raise ValueError(f"{name}.yaml must contain a mapping")
    return data
