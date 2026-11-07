from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from python_sbom import ContentProvider
from python_sbom._collect._content import load_content_provider, provider_script
from python_sbom._errors import SettingsError


@pytest.fixture
def module(tmp_path: Path) -> str:
    # a name unique to the test, so the import cache never hands over another test's module
    (tmp_path / "tools").mkdir()
    provider = """\
from python_sbom import ContentProvider


class Content(ContentProvider):
    pass


instance = Content()
other = object()


class Holder:
    nested = instance
"""
    (tmp_path / "tools" / f"{tmp_path.name}.py").write_text(provider, encoding="utf-8")
    return f"tools.{tmp_path.name}"


@pytest.mark.parametrize(
    "attribute",
    [
        pytest.param("Content", id="class"),
        pytest.param("instance", id="instance"),
        pytest.param("Holder.nested", id="dotted-attribute"),
    ],
)
def test_load_from_project(tmp_path: Path, module: str, attribute: str) -> None:
    provider = load_content_provider(f"{module}:{attribute}", tmp_path)
    assert (type(provider).__name__, provider_script(provider, tmp_path)) == (
        "Content",
        PurePosixPath(f"tools/{tmp_path.name}.py"),
    )


def test_provider_outside_project_is_no_tool(tmp_path: Path) -> None:
    provider = load_content_provider("python_sbom:ContentProvider", tmp_path)
    assert (type(provider), provider_script(provider, tmp_path)) == (ContentProvider, None)


def test_provider_class_outside_project_is_no_tool(tmp_path: Path) -> None:
    class Local(ContentProvider):
        pass

    assert provider_script(Local(), tmp_path) is None


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        pytest.param("tools", "must be `module:attribute`", id="no-attribute"),
        pytest.param(":Content", "must be `module:attribute`", id="no-module"),
        pytest.param("tools:Content:x", "does not load from .*: invalid format", id="two-colons"),
        pytest.param("not_a_module_anywhere:Content", "does not load from .*: No module named", id="import-fails"),
        pytest.param("MODULE:other", "is not a ContentProvider subclass or instance", id="not-a-provider"),
        pytest.param("MODULE:missing", "does not load from .*: .* has no attribute 'missing'", id="missing-attribute"),
    ],
)
def test_load_refuses(tmp_path: Path, module: str, spec: str, message: str) -> None:
    with pytest.raises(SettingsError, match=message):
        load_content_provider(spec.replace("MODULE", module), tmp_path)


def test_provider_without_source_is_no_tool(tmp_path: Path) -> None:
    provider = type("Generated", (ContentProvider,), {"__module__": "not_a_loaded_module"})()
    assert provider_script(provider, tmp_path) is None
