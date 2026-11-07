from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias

from python_sbom._errors import SettingsError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import date, datetime, time

    from python_sbom._model._types import OrganizationalEntity

#: a value of a TOML table, as :mod:`tomllib` or hatchling hand it over
Toml: TypeAlias = "str | int | float | bool | datetime | date | time | list[Toml] | dict[str, Toml]"


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    """
    The options a project sets, in a hatchling hook's table or in ``[tool.python-sbom]``.

    :param supplier: the organization that supplies the project, or ``None`` to name none
    :param repository: the repository URL, or ``None`` to take the first ``Source``, ``Repository`` or ``GitHub``
        project URL of the metadata
    :param default_branch: branch used in links to files in the repository
    :param bundled_wheels: glob patterns, relative to the project root, of wheels the project ships as data files

    """

    supplier: OrganizationalEntity | None
    repository: str | None
    default_branch: str
    bundled_wheels: tuple[str, ...]

    @classmethod
    def from_table(cls, table: Mapping[str, Toml], where: str) -> Settings:
        """
        Read the options from a configuration table, ignoring keys it does not know.

        :param table: the table, with any of ``supplier``, ``repository``, ``default-branch`` and ``bundled-wheels``
        :param where: where the table lives, named in error messages, such as ``[tool.python-sbom]``
        :returns: the settings
        :raises SettingsError: when an option has the wrong type

        """
        supplier = table.get("supplier")
        if supplier is not None and not (
            isinstance(supplier, dict)
            and supplier.keys() <= {"name", "url"}
            and isinstance(name := supplier.get("name"), str)
            and isinstance(urls := supplier.get("url", []), list)
            and all(isinstance(url, str) for url in urls)
        ):
            msg = f"`supplier` in {where} must be a table with a string `name` and an optional `url` string array"
            raise SettingsError(msg)
        if not isinstance(repository := table.get("repository"), str | None):
            msg = f"`repository` in {where} must be a string"
            raise SettingsError(msg)
        if not isinstance(default_branch := table.get("default-branch", "main"), str):
            msg = f"`default-branch` in {where} must be a string"
            raise SettingsError(msg)
        if not (
            isinstance(patterns := table.get("bundled-wheels", []), list)
            and all(isinstance(pattern, str) for pattern in patterns)
        ):
            msg = f"`bundled-wheels` in {where} must be an array of strings"
            raise SettingsError(msg)
        return cls(
            supplier=None if supplier is None else {"name": name, "url": [str(url) for url in urls]},
            repository=None if repository is None else repository.rstrip("/"),
            default_branch=default_branch,
            bundled_wheels=tuple(str(pattern) for pattern in patterns),
        )


__all__ = [
    "Settings",
    "Toml",
]
