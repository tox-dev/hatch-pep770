from __future__ import annotations

import zipfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

import pytest

from python_sbom._errors import SbomError
from python_sbom._wheel._reader import open_artifact


def test_provider_reads_a_member(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("embed/table.py", "x = 1\n")
    with open_artifact(wheel) as opened:
        assert opened.provider_read(PurePosixPath("embed/table.py")) == b"x = 1\n"


def test_provider_read_misses(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("other.py", "")
    with open_artifact(wheel) as opened, pytest.raises(KeyError, match=r"missing\.py"):
        opened.provider_read(PurePosixPath("missing.py"))


def test_artifact_checked_on_open(tmp_path: Path) -> None:
    # the same checks as every other read, so names equal ignoring case are refused before any member is read
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("table.py", "")
        archive.writestr("TABLE.py", "")
    with (
        pytest.raises(SbomError, match=r"holds more than one member named table\.py, ignoring case"),
        ExitStack() as stack,
    ):
        stack.enter_context(open_artifact(wheel))
