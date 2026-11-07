from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError
from python_sbom._model._inputs import ArchiveTree, RecordRow
from python_sbom._model._metadata import parse_metadata
from python_sbom._wheel._archive import member_digest, open_archive, read_member

from ._source import read_bundled_wheels

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path, PurePosixPath

    from python_sbom._model._metadata import CoreMetadata

# a bundled wheel is read whole, to hash it and open it as a zip, so its size is capped as metadata's is
_WHEEL_LIMIT: Final[int] = 512 * 1024 * 1024


def read_archive(archive: Path) -> ArchiveTree:
    # every member is read from the zip by its name, never from a file system path, so a name such as /etc/hostname or
    # ../outside names a member, not a file of the host
    where: Final[str] = archive.name
    with open_archive(archive, where) as handle:
        members: Final[list[str]] = sorted(
            info.filename for info in handle.infolist() if not info.is_dir() and info.filename != f"{where}.cdx.json"
        )
        metadata: Final[dict[str, CoreMetadata]] = {
            _directory(name): parse_metadata(read_member(handle, name, where).decode("utf-8"))
            for name in members
            if name.endswith(".dist-info/METADATA")
        }
        if (top := sum(name.count("/") == 1 and name.endswith(".dist-info/METADATA") for name in members)) != 1:
            msg = f"{where} holds {top} top-level .dist-info/METADATA, not the one naming the project"
            raise SbomError(msg)
        files: Final[dict[str, RecordRow]] = {
            name: RecordRow(
                path=name,
                algorithm="SHA-256",
                digest=member_digest(handle, name, "sha256"),
                size=str(handle.getinfo(name).file_size),
            )
            for name in members
            if not name.endswith(".whl")
        }
    owned: Final[dict[str, list[str]]] = {prefix: [] for prefix in metadata}
    loose: Final[list[str]] = []
    for name in members:
        # the deepest distribution directory that holds the file; the project's own holds every other subdirectory
        if owner := max((prefix for prefix in metadata if prefix and name.startswith(prefix)), key=len, default=""):
            owned[owner].append(name)
        elif "/" in name:
            owned[""].append(name)
        else:
            loose.append(name)
    # in the order the components list them, so the first broken wheel is the one reported
    wheels: Final[list[str]] = []
    for prefix in sorted(metadata):
        wheels.extend(name for name in owned[prefix] if name.endswith(".whl"))
    return ArchiveTree(
        metadata=metadata,
        owned=owned,
        loose=loose,
        files=files,
        bundled=dict(zip(wheels, read_bundled_wheels(wheels, lambda name: BytesIO(_read(archive, name))), strict=True)),
    )


def _directory(name: str) -> str:
    # each distribution by the directory that holds its .dist-info, the project's own at the top level
    return f"{name.rsplit('/', 2)[0]}/" if name.count("/") > 1 else ""


def _read(archive: Path, name: str) -> bytes:
    with open_archive(archive, archive.name) as handle:
        return read_member(handle, name, archive.name, _WHEEL_LIMIT)


def member_reader(artifact: Path) -> Callable[[PurePosixPath], bytes]:
    # what a content provider reads: a member of the built wheel or archive, through the same checks as every read
    def read(path: PurePosixPath) -> bytes:
        with open_archive(artifact, str(artifact)) as handle:
            if str(path) not in handle.namelist():
                raise KeyError(str(path))
            return read_member(handle, str(path), str(artifact))

    return read


__all__ = [
    "member_reader",
    "read_archive",
]
