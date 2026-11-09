from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

import pytest

from python_sbom._backends._sdist import add_to_sdist

if TYPE_CHECKING:
    from pathlib import Path
    from typing import IO


@pytest.fixture
def sdist(tmp_path: Path) -> Path:
    with tarfile.open(path := tmp_path / "example-1.0.tar.gz", "w:gz") as archive:
        directory = tarfile.TarInfo("example-1.0")
        directory.type, directory.mtime = tarfile.DIRTYPE, 100
        archive.addfile(directory)
        source = tarfile.TarInfo("example-1.0/PKG-INFO")
        source.size, source.mtime = 4, 200
        archive.addfile(source, io.BytesIO(b"meta"))
    return path


def test_adds_under_the_top_directory(sdist: Path) -> None:
    add_to_sdist(sdist, ".python-sbom-revision", b"node: x\n")
    with tarfile.open(sdist) as archive:
        added = archive.getmember("example-1.0/.python-sbom-revision")
        handle = archive.extractfile(added)
        assert handle is not None
        assert (archive.getnames(), handle.read(), added.mtime) == (
            ["example-1.0", "example-1.0/PKG-INFO", "example-1.0/.python-sbom-revision"],
            b"node: x\n",
            200,
        )


def test_sdist_already_holding_the_file_is_kept(sdist: Path) -> None:
    # a backend running python-sbom's own plugin under the wrapper records the revision itself
    add_to_sdist(sdist, ".python-sbom-revision", b"node: x\n")
    first = sdist.read_bytes()
    add_to_sdist(sdist, ".python-sbom-revision", b"node: y\n")
    assert sdist.read_bytes() == first


def test_failed_rewrite_keeps_the_sdist(sdist: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = sdist.read_bytes()

    def full_disk(_archive: tarfile.TarFile, _member: tarfile.TarInfo, _content: IO[bytes] | None = None) -> None:
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr(tarfile.TarFile, "addfile", full_disk)
    with pytest.raises(OSError, match="disk full"):
        add_to_sdist(sdist, ".python-sbom-revision", b"node: x\n")
    assert ([path.name for path in sdist.parent.iterdir()], sdist.read_bytes()) == ([sdist.name], original)
