from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

import pytest

from python_sbom import BuiltWheel, MetadataBackend, WheelError

if TYPE_CHECKING:
    from conftest import WriteWheel

    from python_sbom import Settings


def test_metadata_backend(tmp_path: Path, settings: Settings) -> None:
    backend = MetadataBackend(
        root=tmp_path,
        metadata="Name: example\nVersion: 1.0\n",
        wheel_name="example-1.0-py3-none-any.whl",
        settings=settings,
        build_scripts=(PurePosixPath("hatch_build.py"),),
    )
    request = backend.request()
    assert (request.root, request.metadata["Name"], request.wheel_name, request.settings, request.build_scripts) == (
        tmp_path,
        "example",
        "example-1.0-py3-none-any.whl",
        settings,
        (PurePosixPath("hatch_build.py"),),
    )


def test_built_wheel(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(tmp_path / "native-1.0-py3-none-any.whl", {"native-1.0.dist-info/METADATA": b"Name: native\n"})
    request = BuiltWheel(wheel=wheel, root=tmp_path, settings=settings, build_scripts=()).request()
    assert (request.metadata["Name"], request.wheel_name) == ("native", "native-1.0-py3-none-any.whl")


def test_built_wheel_needs_a_wheel(tmp_path: Path, settings: Settings, write_wheel: WriteWheel) -> None:
    archive = write_wheel(tmp_path / "native.whl", {"native/__init__.py": b""}, record=False)
    with pytest.raises(WheelError, match=r"has no \.dist-info/METADATA, so it is not a wheel"):
        BuiltWheel(wheel=archive, root=Path(), settings=settings, build_scripts=()).request()
