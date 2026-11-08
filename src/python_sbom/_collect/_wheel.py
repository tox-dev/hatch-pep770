from __future__ import annotations

from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError
from python_sbom._model._inputs import WheelTree
from python_sbom._wheel._zip import read_wheel_metadata

from ._source import copyright_notice, file_sha256, hash_build_scripts, selected_wheels

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path, PurePosixPath

    from python_sbom._model._inputs import Settings
    from python_sbom._wheel._reader import ArtifactReader


def read_wheel(
    artifact: ArtifactReader, root: Path, settings: Settings, build_scripts: Iterable[PurePosixPath]
) -> WheelTree:
    _, metadata = read_wheel_metadata(artifact.archive, str(artifact.path))
    return WheelTree(
        name=artifact.path.name,
        metadata=metadata,
        copyright=copyright_notice(root, metadata.values("license_files")),
        bundled=artifact.bundled_wheels(_shipped_copies(root, settings, artifact)),
        build_scripts=hash_build_scripts(root, build_scripts),
    )


def _shipped_copies(root: Path, settings: Settings, artifact: ArtifactReader) -> list[str]:
    # the bundled-wheels option selects wheels in the source tree, but the SBOM describes the bytes the artifact ships:
    # each selected wheel is found in the artifact by its digest and read from there, so a wheel changed or left out
    # since the build is refused rather than described; identical copies take the artifact's matching members in turn
    shipped: Final[dict[str, list[str]]] = {}
    for name in sorted(artifact.members):
        if name.endswith(".whl"):
            shipped.setdefault(artifact.digest(name), []).append(name)
    copies: Final[dict[str, Iterator[str]]] = {digest: iter(names) for digest, names in shipped.items()}
    found: Final[list[str]] = []
    for source in selected_wheels(root, settings):
        if (member := next(copies.get(file_sha256(root / source), iter(())), None)) is None:
            msg = (
                f"bundled wheel {source} is not in {artifact.path.name} byte for byte: it changed since the build, or"
                " the build left it out"
            )
            raise SbomError(msg)
        found.append(member)
    return found


__all__ = [
    "read_wheel",
]
