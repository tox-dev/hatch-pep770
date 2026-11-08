from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

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


def test_context_reads_through_its_reader(context_for: ContextFor, tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("embed/table.py", "x = 1\n")
    assert context_for(tmp_path, wheel).read(PurePosixPath("embed/table.py")) == b"x = 1\n"
