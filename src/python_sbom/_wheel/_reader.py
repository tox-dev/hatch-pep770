"""Open a built artifact once and read its members through one checked handle."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING, Final

from ._bundled import read_bundled_wheels
from ._zip import open_archive, read_member, sha256_hex

if TYPE_CHECKING:
    import zipfile
    from collections.abc import Generator
    from pathlib import Path, PurePosixPath

    from python_sbom._model._inputs import BundledWheel

# a bundled wheel is read whole, to hash it and open it as a zip, so its size is capped as metadata's is
_WHEEL_LIMIT: Final[int] = 512 * 1024 * 1024


@contextmanager
def open_artifact(path: Path) -> Generator[ArtifactReader, None, None]:
    # one open zip serves every read of a build, the provider's included, so the archive is checked and indexed once
    with open_archive(path, str(path)) as archive:
        yield ArtifactReader(path=path, archive=archive, members=frozenset(archive.namelist()))


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactReader:
    path: Path
    archive: zipfile.ZipFile
    members: frozenset[str]

    def digest(self, name: str) -> str:
        with self.archive.open(name) as member:
            return sha256_hex(member)

    def provider_read(self, path: PurePosixPath) -> bytes:
        # a provider asking for a member the artifact lacks gets the KeyError a mapping raises, which it may expect
        if (name := str(path)) not in self.members:
            raise KeyError(name)
        return self.read(name)

    def read(self, name: str) -> bytes:
        return read_member(self.archive, name, str(self.path))

    def bundled_wheels(self, names: list[str]) -> list[BundledWheel]:
        # zipfile serializes the seeks of concurrent member reads on its own lock, so the verifying threads share this
        # handle and inflate side by side
        return read_bundled_wheels(
            names, lambda name: BytesIO(read_member(self.archive, name, str(self.path), _WHEEL_LIMIT))
        )


__all__ = [
    "ArtifactReader",
    "open_artifact",
]
