from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from python_sbom._collect._settings import settings_from_pyproject, settings_from_table
from python_sbom._errors import SbomError
from python_sbom._model._inputs import Settings

if TYPE_CHECKING:
    from pathlib import Path

    from python_sbom._collect._settings import Toml


def test_missing_pyproject(tmp_path: Path) -> None:
    with pytest.raises(SbomError, match=r"has no pyproject\.toml to read"):
        settings_from_pyproject(tmp_path)


def test_invalid_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool\n", encoding="utf-8")
    with pytest.raises(SbomError, match=r"pyproject\.toml is not valid TOML"):
        settings_from_pyproject(tmp_path)


def test_defaults(tmp_path: Path, settings: Settings) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'a'\n", encoding="utf-8")
    assert settings_from_pyproject(tmp_path) == settings


def test_table(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.python-sbom]\n"
        "repository = 'https://github.com/example/example/'\n"
        "default-branch = 'dev'\n"
        "bundled-wheels = ['src/*.whl']\n"
        "supplier = { name = 'Example Org' }\n"
        "content-provider = 'sbom:Content'\n",
        encoding="utf-8",
    )
    assert settings_from_pyproject(tmp_path) == Settings(
        supplier={"name": "Example Org", "url": []},
        repository="https://github.com/example/example",
        default_branch="dev",
        bundled_wheels=("src/*.whl",),
        content_provider="sbom:Content",
    )


def test_unknown_option() -> None:
    with pytest.raises(SbomError, match=r"here has unknown option\(s\) bundled, suplier; known: bundled-wheels"):
        settings_from_table({"suplier": {}, "bundled": []}, "here")


@pytest.mark.parametrize(
    ("table", "message"),
    [
        pytest.param({"repository": 1}, "`repository` in here must be a string", id="repository"),
        pytest.param({"default-branch": 1}, "`default-branch` in here must be a string", id="default-branch"),
        pytest.param({"bundled-wheels": "*.whl"}, "`bundled-wheels` in here must be an array", id="bundled-not-list"),
        pytest.param({"bundled-wheels": [1]}, "`bundled-wheels` in here must be an array", id="bundled-not-strings"),
        pytest.param({"content-provider": 1}, "`content-provider` in here must be a string", id="content-provider"),
        pytest.param({"supplier": "Example"}, "`supplier` in here must be a table", id="supplier-not-table"),
        pytest.param({"supplier": {"name": 1}}, "`supplier` in here must be a table", id="supplier-name"),
        pytest.param({"supplier": {"name": "a", "url": "x"}}, "`supplier` in here must be a table", id="supplier-url"),
        pytest.param(
            {"supplier": {"name": "a", "email": "x"}}, "`supplier` in here must be a table", id="supplier-key"
        ),
    ],
)
def test_wrong_type(table: dict[str, Toml], message: str) -> None:
    with pytest.raises(SbomError, match=message):
        settings_from_table(table, "here")


def test_supplier_with_urls() -> None:
    settings = settings_from_table({"supplier": {"name": "Example Org", "url": ["https://example.org"]}}, "here")
    assert settings.supplier == {"name": "Example Org", "url": ["https://example.org"]}
