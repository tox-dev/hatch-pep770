from __future__ import annotations

import dataclasses
import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._collect._source import read_source_tree, wheel_request
from python_sbom._errors import SbomError
from python_sbom._model._inputs import BuildScript, SbomRequest
from python_sbom._model._metadata import parse_metadata

if TYPE_CHECKING:
    from collections.abc import Mapping

    from conftest import WriteWheel

    from python_sbom._model._inputs import Settings

_PIP: Final[dict[str, bytes]] = {"pip/__init__.py": b"", "pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\n"}


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        pytest.param({}, None, id="no-license-file"),
        pytest.param({"LICENSE": "MIT terms\n"}, None, id="no-copyright-line"),
        pytest.param(
            {"LICENSE": "MIT\n\nCopyright (c) 2026 Example\nCopyright (c) 2025 Other\n"},
            "Copyright (c) 2026 Example",
            id="first-copyright-line",
        ),
    ],
)
def test_copyright(tmp_path: Path, settings: Settings, files: Mapping[str, str], expected: str | None) -> None:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    source = read_source_tree(request(tmp_path, settings, "License-File: LICENSE\nLicense-File: NOTICE\n"))
    assert source.copyright == expected


def request(root: Path, settings: Settings, metadata: str = "", scripts: tuple[PurePosixPath, ...] = ()) -> SbomRequest:
    return SbomRequest(
        root=root,
        metadata=parse_metadata(f"Name: example\nVersion: 1.0\n{metadata}"),
        wheel_name="example-1.0-py3-none-any.whl",
        settings=settings,
        build_scripts=scripts,
    )


def test_bundled_wheels_sorted_once(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    for directory in ("b", "a"):
        write_wheel(tmp_path / "src" / directory / "pip-1.0-py3-none-any.whl", _PIP)
    settings = dataclasses.replace(settings, bundled_wheels=("src/*/*.whl", "src/a/*.whl"))
    paths = [wheel.path for wheel in read_source_tree(request(tmp_path, settings)).bundled]
    assert paths == ["src/a/pip-1.0-py3-none-any.whl", "src/b/pip-1.0-py3-none-any.whl"]


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("../outside/*.whl", id="parent"),
        pytest.param("src/../../outside/*.whl", id="parent-after-directory"),
        pytest.param("ROOT/outside/*.whl", id="absolute"),
    ],
)
def test_bundled_wheel_pattern_outside_project(
    tmp_path: Path, settings: Settings, write_wheel: WriteWheel, pattern: str
) -> None:
    write_wheel(tmp_path / "outside" / "pip-1.0-py3-none-any.whl", _PIP)
    (project := tmp_path / "project" / "src").mkdir(parents=True)
    pattern = pattern.replace("ROOT", tmp_path.as_posix())
    settings = dataclasses.replace(settings, bundled_wheels=(pattern,))
    with pytest.raises(SbomError, match=f"`bundled-wheels` pattern {re.escape(repr(pattern))} must be relative"):
        read_source_tree(request(project.parent, settings))


def test_build_scripts_hashed(tmp_path: Path, settings: Settings) -> None:
    (tmp_path / "hatch_build.py").write_bytes(b"hook = 1\n")
    script = PurePosixPath("hatch_build.py")
    source = read_source_tree(request(tmp_path, settings, scripts=(script,)))
    assert source.build_scripts == [BuildScript(path=script, sha256=hashlib.sha256(b"hook = 1\n").hexdigest())]


def test_build_script_outside_project(tmp_path: Path, settings: Settings) -> None:
    # a custom hook path may be absolute, which on Windows carries a drive the join with the root must keep
    (tmp_path / "hatch_build.py").write_bytes(b"hook = 1\n")
    script = PurePosixPath((tmp_path / "hatch_build.py").as_posix())
    source = read_source_tree(request(tmp_path / "project", settings, scripts=(script,)))
    assert source.build_scripts == [BuildScript(path=script, sha256=hashlib.sha256(b"hook = 1\n").hexdigest())]


def test_wheel_request(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(tmp_path / "native-1.0-py3-none-any.whl", {"native-1.0.dist-info/METADATA": b"Name: native\n"})
    request = wheel_request(wheel, tmp_path, settings, (PurePosixPath("build.py"),))
    assert (request.root, request.metadata.name, request.wheel_name, request.settings, request.build_scripts) == (
        tmp_path,
        "native",
        "native-1.0-py3-none-any.whl",
        settings,
        (PurePosixPath("build.py"),),
    )


@pytest.mark.parametrize(
    ("name", "message"),
    [
        pytest.param("native.whl", "is not a wheel: Not a valid wheel filename", id="file-name"),
        pytest.param(
            "native-1.0-py3-none-any.whl",
            r"is not a wheel: Wheel doesn't contain exactly one \.dist-info directory",
            id="no-dist-info",
        ),
    ],
)
def test_wheel_request_needs_a_wheel(
    tmp_path: Path, settings: Settings, write_wheel: WriteWheel, name: str, message: str
) -> None:
    archive = write_wheel(tmp_path / name, {"native/__init__.py": b""}, record=False)
    with pytest.raises(SbomError, match=message):
        wheel_request(archive, Path(), settings, ())
