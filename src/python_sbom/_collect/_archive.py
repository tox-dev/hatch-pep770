from __future__ import annotations

from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError
from python_sbom._model._archive import bundled_members
from python_sbom._model._inputs import ArchiveTree, RecordRow
from python_sbom._model._metadata import parse_metadata
from python_sbom._model._names import archive_sbom_file_name

if TYPE_CHECKING:
    from collections.abc import Container

    from python_sbom._model._metadata import CoreMetadata
    from python_sbom._wheel._reader import ArtifactReader


def read_archive(artifact: ArtifactReader) -> ArchiveTree:
    # every member is read from the zip by its name, never from a file system path, so a name such as /etc/hostname or
    # ../outside names a member, not a file of the host
    where: Final[str] = artifact.path.name
    members: Final[list[str]] = sorted(
        info.filename
        for info in artifact.archive.infolist()
        if not info.is_dir() and info.filename != archive_sbom_file_name(where)
    )
    metadata: Final[dict[str, CoreMetadata]] = {}
    for name in members:
        if not name.endswith(".dist-info/METADATA"):
            continue
        # files belong to a distribution by the directory that holds its .dist-info, which two cannot share
        if (directory := _distribution_prefix(name)) in metadata:
            msg = (
                f"{where} holds more than one .dist-info in {directory or 'its top level'}, so their files cannot"
                " be told apart"
            )
            raise SbomError(msg)
        metadata[directory] = parse_metadata(artifact.read(name).decode("utf-8"))
    if "" not in metadata:
        msg = f"{where} holds no top-level .dist-info/METADATA naming the project"
        raise SbomError(msg)
    files: Final[dict[str, RecordRow]] = {
        name: RecordRow(
            path=name,
            algorithm="SHA-256",
            digest=artifact.digest(name),
            size=str(artifact.archive.getinfo(name).file_size),
        )
        for name in members
        if not name.endswith(".whl")
    }
    owned: Final[dict[str, list[str]]] = {prefix: [] for prefix in metadata}
    loose: Final[list[str]] = []
    for name in members:
        # the project's own distribution holds every subdirectory no other one does
        if owner := _owner(name, metadata):
            owned[owner].append(name)
        elif "/" in name:
            owned[""].append(name)
        else:
            loose.append(name)
    # in the order the components list them, so the first broken wheel is the one reported
    wheels: Final[list[str]] = [member for member in bundled_members(loose, owned) if not member.endswith("/")]
    return ArchiveTree(
        metadata=metadata,
        owned=owned,
        loose=loose,
        files=files,
        bundled=dict(zip(wheels, artifact.bundled_wheels(wheels), strict=True)),
    )


def _distribution_prefix(name: str) -> str:
    # each distribution by the directory that holds its .dist-info, the project's own at the top level
    return f"{name.rsplit('/', 2)[0]}/" if name.count("/") > 1 else ""


def _owner(name: str, distributions: Container[str]) -> str | None:
    # the deepest distribution directory that holds the member, found by looking up each of its ancestor directories,
    # deepest first, so the work grows with the member's depth rather than the number of distributions
    parents: Final[list[str]] = name.split("/")[:-1]
    return next(
        (
            prefix
            for depth in range(len(parents), 0, -1)
            if (prefix := f"{'/'.join(parents[:depth])}/") in distributions
        ),
        None,
    )


__all__ = [
    "read_archive",
]
