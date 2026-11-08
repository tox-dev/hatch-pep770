from __future__ import annotations

import dataclasses
import sys
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

import pytest

import python_sbom
from python_sbom import ContentProvider
from python_sbom._collect._content import resolve_provider
from python_sbom._errors import SbomError

if TYPE_CHECKING:
    from python_sbom import Settings


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
def test_load_from_project(tmp_path: Path, module: str, attribute: str, settings: Settings) -> None:
    provider, scripts = resolve_provider(f"{module}:{attribute}", settings, tmp_path)
    assert (type(provider).__name__, scripts) == ("Content", (PurePosixPath(f"tools/{tmp_path.name}.py"),))


def test_option_names_the_provider(tmp_path: Path, module: str, settings: Settings) -> None:
    configured = dataclasses.replace(settings, content_provider=f"{module}:Content")
    assert type(resolve_provider(None, configured, tmp_path)[0]).__name__ == "Content"


def test_given_name_wins_over_option(tmp_path: Path, module: str, settings: Settings) -> None:
    configured = dataclasses.replace(settings, content_provider="not_a_module_anywhere:Content")
    assert type(resolve_provider(f"{module}:Content", configured, tmp_path)[0]).__name__ == "Content"


def test_given_instance_wins_over_option(tmp_path: Path, settings: Settings) -> None:
    # even one that is falsy, as a provider defining __len__ may be
    class Empty(ContentProvider):
        def __len__(self) -> int:
            return 0

    given = Empty()
    assert not given
    configured = dataclasses.replace(settings, content_provider="not_a_module_anywhere:Content")
    assert resolve_provider(given, configured, tmp_path) == (given, ())


def test_no_provider_adds_nothing_and_is_no_tool(settings: Settings) -> None:
    # python-sbom's own no-op provider is no build tool, not even when python-sbom builds itself
    provider, scripts = resolve_provider(None, settings, Path(python_sbom.__file__).parents[2])
    assert (type(provider), scripts) == (ContentProvider, ())


def test_project_base_classes_are_tools(tmp_path: Path, settings: Settings) -> None:
    # a base class in the project shapes the document as much as the provider class itself
    (package := tmp_path / f"bases_{tmp_path.name}").mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "base.py").write_text(
        "from python_sbom import ContentProvider\n\n\nclass Base(ContentProvider):\n    pass\n", encoding="utf-8"
    )
    (package / "leaf.py").write_text("from .base import Base\n\n\nclass Leaf(Base):\n    pass\n", encoding="utf-8")
    _, scripts = resolve_provider(f"{package.name}.leaf:Leaf", settings, tmp_path)
    assert scripts == (PurePosixPath(f"{package.name}/leaf.py"), PurePosixPath(f"{package.name}/base.py"))


def test_provider_class_outside_project_is_no_tool(tmp_path: Path, settings: Settings) -> None:
    class Local(ContentProvider):
        pass

    assert resolve_provider(Local(), settings, tmp_path)[1] == ()


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
def test_load_refuses(tmp_path: Path, module: str, spec: str, message: str, settings: Settings) -> None:
    with pytest.raises(SbomError, match=message):
        resolve_provider(spec.replace("MODULE", module), settings, tmp_path)


def test_provider_without_source_is_no_tool(tmp_path: Path, settings: Settings) -> None:
    provider = type("Generated", (ContentProvider,), {"__module__": "not_a_loaded_module"})()
    assert resolve_provider(provider, settings, tmp_path)[1] == ()


@pytest.mark.parametrize(
    "layout",
    [pytest.param("{name}.py", id="module"), pytest.param("{name}/__init__.py", id="package")],
)
def test_provider_of_another_project_loads_its_own(tmp_path: Path, settings: Settings, layout: str) -> None:
    # two projects whose providers share a module name, built in one process as hatch builds them or a test suite builds
    # copies of one project
    name = f"provider_{tmp_path.name}"
    for project, value in (("first", "1"), ("second", "2")):
        (source := tmp_path / project / layout.format(name=name)).parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            f"from python_sbom import ContentProvider\n\n\nclass Content(ContentProvider):\n    value = {value}\n",
            encoding="utf-8",
        )
    try:
        first, _ = resolve_provider(f"{name}:Content", settings, tmp_path / "first")
        second, scripts = resolve_provider(f"{name}:Content", settings, tmp_path / "second")
    finally:
        sys.modules.pop(name, None)
    assert (getattr(first, "value", None), getattr(second, "value", None), scripts) == (
        1,
        2,
        (PurePosixPath(layout.format(name=name)),),
    )


def test_provider_of_the_same_project_loads_again(tmp_path: Path, module: str, settings: Settings) -> None:
    first, _ = resolve_provider(f"{module}:Content", settings, tmp_path)
    second, _ = resolve_provider(f"{module}:Content", settings, tmp_path)
    assert type(first) is type(second)
