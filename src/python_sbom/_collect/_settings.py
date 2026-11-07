from __future__ import annotations

import tomllib
from typing import TYPE_CHECKING, TypeAlias

from python_sbom._errors import SettingsError
from python_sbom._model._inputs import Settings

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import date, datetime, time
    from pathlib import Path
    from typing import TypeIs  # new in 3.13; annotations here are never evaluated

    from python_sbom._model._types import OrganizationalEntity

#: a value of a TOML table, as :mod:`tomllib` or hatchling hand it over
Toml: TypeAlias = "str | int | float | bool | datetime | date | time | list[Toml] | dict[str, Toml]"


def settings_from_pyproject(root: Path, overrides: Mapping[str, Toml]) -> Settings:
    pyproject = root / "pyproject.toml"
    try:
        loaded = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        msg = f"{root} has no pyproject.toml to read [tool.python-sbom] from"
        raise SettingsError(msg) from error
    except tomllib.TOMLDecodeError as error:
        msg = f"{pyproject} is not valid TOML: {error}"
        raise SettingsError(msg) from error
    table = loaded.get("tool", {}).get("python-sbom", {})
    return settings_from_table({**table, **overrides}, f"[tool.python-sbom] of {pyproject}")


def settings_from_table(table: Mapping[str, Toml], where: str) -> Settings:
    known = {"bundled-wheels", "content-provider", "default-branch", "repository", "supplier"}
    if unknown := sorted(table.keys() - known):
        msg = f"{where} has unknown option(s) {', '.join(unknown)}; known: {', '.join(sorted(known))}"
        raise SettingsError(msg)
    if not isinstance(repository := table.get("repository"), str | None):
        msg = f"`repository` in {where} must be a string"
        raise SettingsError(msg)
    if not isinstance(default_branch := table.get("default-branch", "main"), str):
        msg = f"`default-branch` in {where} must be a string"
        raise SettingsError(msg)
    if not _strings(patterns := table.get("bundled-wheels", [])):
        msg = f"`bundled-wheels` in {where} must be an array of strings"
        raise SettingsError(msg)
    if not isinstance(content_provider := table.get("content-provider"), str | None):
        msg = f"`content-provider` in {where} must be a string, `module:attribute`"
        raise SettingsError(msg)
    return Settings(
        supplier=_supplier(table.get("supplier"), where),
        repository=None if repository is None else repository.rstrip("/"),
        default_branch=default_branch,
        bundled_wheels=tuple(patterns),
        content_provider=content_provider,
    )


def _strings(values: object) -> TypeIs[list[str]]:
    return isinstance(values, list) and all(isinstance(value, str) for value in values)


def _supplier(value: Toml | None, where: str) -> OrganizationalEntity | None:
    if value is None:
        return None
    if (
        isinstance(value, dict)
        and value.keys() <= {"name", "url"}
        and isinstance(name := value.get("name"), str)
        and _strings(urls := value.get("url", []))
    ):
        return {"name": name, "url": urls}
    msg = f"`supplier` in {where} must be a table with a string `name` and an optional `url` string array"
    raise SettingsError(msg)


__all__ = [
    "Toml",
    "settings_from_pyproject",
    "settings_from_table",
]
