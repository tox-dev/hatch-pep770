from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import SbomError
from python_sbom._collect._wheel import read_wheel
from python_sbom._model._inputs import BuildScript, WheelTree
from python_sbom._wheel._reader import open_artifact

if TYPE_CHECKING:
    from collections.abc import Mapping

    from conftest import WriteWheel

    from python_sbom._model._inputs import Settings

_PIP: Final[dict[str, bytes]] = {"pip/__init__.py": b"", "pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\n"}
_NATIVE: Final[dict[str, bytes]] = {
    "native-1.0.dist-info/METADATA": b"Name: native\nVersion: 1.0\nLicense-File: LICENSE\n"
}


def test_read_wheel(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    (tmp_path / "LICENSE").write_text("MIT\n\nCopyright (c) 2026 Example\n", encoding="utf-8")
    (tmp_path / "hatch_build.py").write_bytes(b"hook = 1\n")
    tree = tree_of(
        write_wheel(tmp_path / "native-1.0-py3-none-any.whl", _NATIVE),
        tmp_path,
        settings,
        PurePosixPath("hatch_build.py"),
    )
    assert (tree.name, tree.metadata.name, tree.copyright, tree.bundled, tree.build_scripts) == (
        "native-1.0-py3-none-any.whl",
        "native",
        "Copyright (c) 2026 Example",
        [],
        [BuildScript(path=PurePosixPath("hatch_build.py"), sha256=hashlib.sha256(b"hook = 1\n").hexdigest())],
    )


def tree_of(wheel: Path, root: Path, settings: Settings, *scripts: PurePosixPath) -> WheelTree:
    with open_artifact(wheel) as artifact:
        return read_wheel(artifact, root, settings, scripts)


def test_bundled_wheels_read_from_the_wheel(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    # identical copies, selected twice over, take the wheel's copies in turn, each keeping an identity of its own
    for directory in ("b", "a"):
        content = write_wheel(tmp_path / "src" / directory / "pip-1.0-py3-none-any.whl", _PIP).read_bytes()
    wheel = built(
        write_wheel, tmp_path, {"pkg/b/pip-1.0-py3-none-any.whl": content, "pkg/a/pip-1.0-py3-none-any.whl": content}
    )
    settings = dataclasses.replace(settings, bundled_wheels=("src/*/*.whl", "src/a/*.whl"))
    assert [bundled.path for bundled in tree_of(wheel, tmp_path, settings).bundled] == [
        "pkg/a/pip-1.0-py3-none-any.whl",
        "pkg/b/pip-1.0-py3-none-any.whl",
    ]


def built(write_wheel: WriteWheel, root: Path, bundled: Mapping[str, bytes]) -> Path:
    return write_wheel(root / "dist" / "native-1.0-py3-none-any.whl", {**_NATIVE, **bundled})


@pytest.mark.parametrize(
    "shipped",
    [
        pytest.param({"pkg/pip-1.0-py3-none-any.whl": b"the bytes of the build"}, id="changed-since-the-build"),
        pytest.param({}, id="left-out-of-the-build"),
    ],
)
def test_bundled_wheel_not_shipped_is_refused(
    tmp_path: Path, settings: Settings, write_wheel: WriteWheel, shipped: dict[str, bytes]
) -> None:
    write_wheel(tmp_path / "src" / "pip-1.0-py3-none-any.whl", _PIP)
    settings = dataclasses.replace(settings, bundled_wheels=("src/*.whl",))
    message = r"bundled wheel src/pip-1\.0-py3-none-any\.whl is not in native-1\.0-py3-none-any\.whl byte for byte"
    with pytest.raises(SbomError, match=message):
        tree_of(built(write_wheel, tmp_path, shipped), tmp_path, settings)


def test_more_bundled_copies_than_shipped_is_refused(
    tmp_path: Path, settings: Settings, write_wheel: WriteWheel
) -> None:
    for directory in ("a", "b"):
        content = write_wheel(tmp_path / "src" / directory / "pip-1.0-py3-none-any.whl", _PIP).read_bytes()
    settings = dataclasses.replace(settings, bundled_wheels=("src/*/*.whl",))
    with pytest.raises(SbomError, match=r"bundled wheel src/b/pip-1\.0-py3-none-any\.whl is not in native"):
        tree_of(built(write_wheel, tmp_path, {"pkg/pip-1.0-py3-none-any.whl": content}), tmp_path, settings)


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
def test_read_wheel_needs_a_wheel(
    tmp_path: Path, settings: Settings, write_wheel: WriteWheel, name: str, message: str
) -> None:
    archive = write_wheel(tmp_path / name, {"native/__init__.py": b""}, record=False)
    with pytest.raises(SbomError, match=message):
        tree_of(archive, Path(), settings)
