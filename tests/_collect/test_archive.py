from __future__ import annotations

import hashlib
import zipfile
from typing import TYPE_CHECKING

import pytest

from python_sbom._collect._archive import read_archive
from python_sbom._wheel._reader import open_artifact

if TYPE_CHECKING:
    from pathlib import Path


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
    with open_artifact(archive) as opened:
        row = read_archive(opened).files[name]
    assert (row.digest, row.size) == (hashlib.sha256(b"inside the archive").hexdigest(), "18")
