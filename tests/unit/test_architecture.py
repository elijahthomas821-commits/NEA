"""Static checks on the code base (part of the security review, run on every CI build).

* The analysis package is pure: no database, network or framework imports.
* Only two modules talk to the outside world: the Telegram client and the AI provider. Nothing
  fetches marketplace pages (listings are entered by hand), so there is no scraping and no
  server-side request forgery surface.
* No dynamic code execution, unsafe deserialisation or shell commands.
* SQL text is never built from strings.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[2] / "app"


def modules(package: str = "") -> list[Path]:
    return sorted(p for p in (APP / package).rglob("*.py") if "__pycache__" not in p.parts)


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def rel(path: Path) -> str:
    return str(path.relative_to(APP.parent))


FORBIDDEN_IN_ANALYSIS = (
    "sqlalchemy", "httpx", "httpx2", "requests", "fastapi", "starlette", "celery", "redis",
    "anthropic", "psycopg", "app.services", "app.models", "app.database", "app.api",
    "app.workers", "app.notifications", "app.collectors", "socket", "subprocess",
)  # fmt: skip


@pytest.mark.parametrize("path", modules("analysis"), ids=rel)
def test_analysis_is_pure(path):
    bad = {
        name
        for name in imported_names(path)
        for forbidden in FORBIDDEN_IN_ANALYSIS
        if name == forbidden or name.startswith(forbidden + ".")
    }
    assert not bad, f"{rel(path)} imports {sorted(bad)}"


NETWORK_CLIENTS = {
    "httpx": {"app/notifications/telegram/client.py"},
    "anthropic": {"app/services/ai/anthropic_provider.py"},
}
NEVER_IMPORTED = ("requests", "urllib.request", "aiohttp", "socket", "http.client", "pickle",
                  "marshal", "shelve", "subprocess")  # fmt: skip


def test_outbound_network_access_is_confined():
    users: dict[str, set[str]] = {name: set() for name in NETWORK_CLIENTS}
    for path in modules():
        names = imported_names(path)
        for client in NETWORK_CLIENTS:
            if any(n == client or n.startswith(client + ".") for n in names):
                users[client].add(rel(path))
        banned = [n for n in names for b in NEVER_IMPORTED if n == b or n.startswith(b + ".")]
        assert not banned, f"{rel(path)} imports {banned}"
    assert users == NETWORK_CLIENTS


def test_no_marketplace_network_client():
    """Listing intake is manual: the Vinted module only parses links you paste."""
    for path in modules("collectors"):
        assert not imported_names(path) & {"httpx", "httpx2", "anthropic"}, rel(path)


DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__"}


@pytest.mark.parametrize("path", modules(), ids=rel)
def test_no_dangerous_calls(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in DANGEROUS_CALLS:
            pytest.fail(f"{rel(path)}:{node.lineno} calls {func.id}()")
        if isinstance(func, ast.Attribute):
            if func.attr == "load" and isinstance(func.value, ast.Name) and func.value.id == "yaml":
                pytest.fail(f"{rel(path)}:{node.lineno} uses yaml.load (use safe_load)")
            if func.attr == "system" and isinstance(func.value, ast.Name) and func.value.id == "os":
                pytest.fail(f"{rel(path)}:{node.lineno} calls os.system")
        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value
            ):
                pytest.fail(f"{rel(path)}:{node.lineno} runs a shell")
            if (
                keyword.arg == "verify"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
            ):
                pytest.fail(f"{rel(path)}:{node.lineno} disables TLS verification")


@pytest.mark.parametrize("path", modules(), ids=rel)
def test_sql_text_is_never_built_from_strings(path):
    """``text()`` only ever receives literal SQL; values go in as bound parameters."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "text"
            and node.args
            and not isinstance(node.args[0], ast.Constant)
        ):
            pytest.fail(f"{rel(path)}:{node.lineno} passes a non-literal to text()")


MONEY_WORDS = ("price", "cost", "profit", "fee", "amount", "value", "roi", "margin", "pay")


def _schema_field_names(schema: dict) -> set[str]:
    names: set[str] = set()
    for definition in [schema, *schema.get("$defs", {}).values()]:
        names.update(definition.get("properties", {}))
    return names


def test_ai_output_has_no_path_into_money():
    """The AI response schema contains no money-like field, and extra fields are rejected, so a
    model's answer can never carry a number into price, cost or profit calculations."""
    from pydantic import ValidationError

    from app.services.ai.schemas import AIListingAnalysis

    names = _schema_field_names(AIListingAnalysis.model_json_schema())
    assert names, "schema has fields"
    assert not [n for n in names if any(word in n.lower() for word in MONEY_WORDS)]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AIListingAnalysis.model_validate(
            {"brand": "stone-island", "category": "sweatshirts",
             "identification_confidence": "0.9", "expected_price": "120"}
        )  # fmt: skip


def test_money_code_does_not_import_ai():
    for package in ("analysis/profit", "analysis/pricing", "analysis/market", "analysis/deals"):
        for path in modules(package):
            assert not any("ai" in name.split(".") for name in imported_names(path)), rel(path)
