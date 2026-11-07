from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

import pytest

from python_sbom import BundledWheelInfo, ContentProvider, Contributions

if TYPE_CHECKING:
    from conftest import ContextFor


def test_default_provider_adds_nothing_to_bundled_wheels(context_for: ContextFor) -> None:
    info = ContentProvider().bundled_wheel(context_for(Path(), Path()), PurePosixPath("a.whl"))
    assert info == BundledWheelInfo()


def test_default_provider_contributes_nothing(context_for: ContextFor) -> None:
    assert ContentProvider().contributions(context_for(Path(), Path())) == Contributions()


def test_context_carries_project(context_for: ContextFor, tmp_path: Path) -> None:
    context = context_for(tmp_path, tmp_path)
    assert (context.root, context.identity.property_prefix, context.settings.default_branch) == (
        tmp_path,
        "example",
        "main",
    )


def test_context_reads_a_directory(tmp_path: Path, context_for: ContextFor) -> None:
    (tmp_path / "embed").mkdir()
    (tmp_path / "embed" / "table.py").write_bytes(b"x = 1\n")
    assert context_for(tmp_path, tmp_path).read(PurePosixPath("embed/table.py")) == b"x = 1\n"


def test_context_reads_a_zip(tmp_path: Path, context_for: ContextFor) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("embed/table.py", "x = 1\n")
    assert context_for(tmp_path, wheel).read(PurePosixPath("embed/table.py")) == b"x = 1\n"


@pytest.mark.parametrize("artifact", [pytest.param("dir", id="directory"), pytest.param("a.whl", id="zip")])
def test_context_misses(tmp_path: Path, context_for: ContextFor, artifact: str) -> None:
    (tmp_path / "dir").mkdir()
    with zipfile.ZipFile(tmp_path / "a.whl", "w") as archive:
        archive.writestr("other.py", "")
    with pytest.raises(KeyError):
        context_for(tmp_path, tmp_path / artifact).read(PurePosixPath("missing.py"))
