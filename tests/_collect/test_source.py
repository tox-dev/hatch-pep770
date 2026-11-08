from __future__ import annotations

import dataclasses
import hashlib
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

import pytest

from python_sbom._collect._source import copyright_notice, hash_build_scripts, selected_wheels
from python_sbom._errors import SbomError
from python_sbom._model._inputs import BuildScript

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from python_sbom._model._inputs import Settings


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
def test_copyright(tmp_path: Path, files: Mapping[str, str], expected: str | None) -> None:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    assert copyright_notice(tmp_path, ["LICENSE", "NOTICE"]) == expected


def test_selected_wheels_sorted_once(tmp_path: Path, settings: Settings) -> None:
    for directory in ("b", "a"):
        (tmp_path / "src" / directory).mkdir(parents=True)
        (tmp_path / "src" / directory / "pip-1.0-py3-none-any.whl").write_bytes(b"")
    settings = dataclasses.replace(settings, bundled_wheels=("src/*/*.whl", "src/a/*.whl"))
    assert selected_wheels(tmp_path, settings) == ["src/a/pip-1.0-py3-none-any.whl", "src/b/pip-1.0-py3-none-any.whl"]


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("../outside/*.whl", id="parent"),
        pytest.param("src/../../outside/*.whl", id="parent-after-directory"),
        pytest.param("ROOT/outside/*.whl", id="absolute"),
    ],
)
def test_bundled_wheel_pattern_outside_project(tmp_path: Path, settings: Settings, pattern: str) -> None:
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "pip-1.0-py3-none-any.whl").write_bytes(b"")
    (project := tmp_path / "project" / "src").mkdir(parents=True)
    pattern = pattern.replace("ROOT", tmp_path.as_posix())
    settings = dataclasses.replace(settings, bundled_wheels=(pattern,))
    with pytest.raises(SbomError, match=f"`bundled-wheels` pattern {re.escape(repr(pattern))} must be relative"):
        selected_wheels(project.parent, settings)


def test_build_scripts_hashed_once(tmp_path: Path) -> None:
    (tmp_path / "hatch_build.py").write_bytes(b"hook = 1\n")
    script = PurePosixPath("hatch_build.py")
    assert hash_build_scripts(tmp_path, [script, script]) == [
        BuildScript(path=script, sha256=hashlib.sha256(b"hook = 1\n").hexdigest())
    ]


def test_build_script_outside_project(tmp_path: Path) -> None:
    # a custom hook path may be absolute, which on Windows carries a drive the join with the root must keep
    (tmp_path / "hatch_build.py").write_bytes(b"hook = 1\n")
    script = PurePosixPath((tmp_path / "hatch_build.py").as_posix())
    assert hash_build_scripts(tmp_path / "project", [script]) == [
        BuildScript(path=script, sha256=hashlib.sha256(b"hook = 1\n").hexdigest())
    ]
