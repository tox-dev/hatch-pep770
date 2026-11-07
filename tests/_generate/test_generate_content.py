from __future__ import annotations

from email import message_from_string
from pathlib import Path, PurePosixPath

import pytest

from python_sbom import (
    BundledWheel,
    BundledWheelInfo,
    ContentProvider,
    Contributions,
    SbomRequest,
    Settings,
    SettingsError,
    load_content_provider,
)


def test_default_provider_adds_nothing_to_bundled_wheels() -> None:
    wheel = BundledWheel(
        path="a.whl", sha256="", metadata_name="", metadata=message_from_string(""), files=[], vendored=[]
    )
    assert ContentProvider().bundled_wheel(wheel) == BundledWheelInfo(properties=[], supplier=None)


def test_default_provider_contributes_nothing(settings: Settings) -> None:
    request = SbomRequest(
        root=Path(), metadata=message_from_string(""), wheel_name="", settings=settings, build_scripts=()
    )
    assert ContentProvider().contributions(request) == Contributions(
        components=[], dependencies=[], root_properties=[], tools=[]
    )


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
"""
    (tmp_path / "tools" / f"{tmp_path.name}.py").write_text(provider, encoding="utf-8")
    return f"tools.{tmp_path.name}"


@pytest.mark.parametrize("attribute", [pytest.param("Content", id="class"), pytest.param("instance", id="instance")])
def test_load_from_project(tmp_path: Path, module: str, attribute: str) -> None:
    provider, script = load_content_provider(f"{module}:{attribute}", tmp_path)
    assert type(provider).__name__ == "Content"
    assert script == PurePosixPath(f"tools/{tmp_path.name}.py")


def test_load_from_outside_project(tmp_path: Path) -> None:
    provider, script = load_content_provider("python_sbom:ContentProvider", tmp_path)
    assert type(provider) is ContentProvider
    assert script is None


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        pytest.param("tools", "must be `module:attribute`", id="no-attribute"),
        pytest.param(":Content", "must be `module:attribute`", id="no-module"),
        pytest.param("not_a_module_anywhere:Content", "does not import from", id="import-fails"),
        pytest.param("MODULE:other", "is not a ContentProvider subclass or instance", id="not-a-provider"),
        pytest.param("MODULE:missing", "is not a ContentProvider subclass or instance", id="missing-attribute"),
    ],
)
def test_load_refuses(tmp_path: Path, module: str, spec: str, message: str) -> None:
    with pytest.raises(SettingsError, match=message):
        load_content_provider(spec.replace("MODULE", module), tmp_path)
