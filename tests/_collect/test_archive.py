from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from python_sbom._collect._archive import member_reader, read_archive
from python_sbom._errors import WheelError


def test_member_reader_reads_a_member(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("embed/table.py", "x = 1\n")
    assert member_reader(wheel)(PurePosixPath("embed/table.py")) == b"x = 1\n"


def test_member_reader_misses(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("other.py", "")
    with pytest.raises(KeyError, match=r"missing\.py"):
        member_reader(wheel)(PurePosixPath("missing.py"))


def test_member_reader_checks_the_archive(tmp_path: Path) -> None:
    # the same checks as every other read, so names equal ignoring case are refused here too
    with zipfile.ZipFile(wheel := tmp_path / "a.whl", "w") as archive:
        archive.writestr("table.py", "")
        archive.writestr("TABLE.py", "")
    with pytest.raises(WheelError, match=r"holds more than one member named table\.py, ignoring case"):
        member_reader(wheel)(PurePosixPath("table.py"))


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("/etc/hostname", id="absolute"),
        pytest.param("lib/../../../../etc/os-release", id="parent"),
        pytest.param("sub/../../outside.txt", id="outside"),
    ],
)
def test_archive_member_names_never_reach_the_host(tmp_path: Path, name: str) -> None:
    # each member is hashed from the zip, so a name that would point outside an unpacked copy names the member alone
    with zipfile.ZipFile(archive := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\n")
        handle.writestr(zipfile.ZipInfo(name), b"inside the archive")
    row = read_archive(archive).files[name]
    assert (row.digest, row.size) == (hashlib.sha256(b"inside the archive").hexdigest(), "18")
