from __future__ import annotations

import dataclasses
import hashlib
from pathlib import PurePath
from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError
from python_sbom._model._inputs import BuildScript, SbomRequest, SourceTree
from python_sbom._wheel._archive import open_archive, read_wheel_metadata
from python_sbom._wheel._bundled import read_bundled_wheels

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path, PurePosixPath

    from python_sbom._model._inputs import Settings


def read_source_tree(request: SbomRequest, *, inside: Mapping[str, str]) -> SourceTree:
    # inside maps a wheel's sha256 to its path in the built artifact: a bundled wheel the artifact holds is named by
    # that path, as an archive SBOM names it, so both documents give one wheel the same identity
    root = request.root
    wheels: Final[set[str]] = set()
    for pattern in request.settings.bundled_wheels:
        # a wheel outside the project is none the project ships, and pathlib refuses an absolute pattern outright
        if (path := PurePath(pattern)).anchor or ".." in path.parts:
            msg = f"`bundled-wheels` pattern {pattern!r} must be relative to the project, without `..`"
            raise SbomError(msg)
        wheels.update(wheel.relative_to(root).as_posix() for wheel in root.glob(pattern))
    return SourceTree(
        copyright=copyright_notice(root, request.metadata.values("license_files")),
        bundled=[
            dataclasses.replace(wheel, path=inside.get(wheel.sha256, wheel.path))
            for wheel in read_bundled_wheels(sorted(wheels), lambda path: (root / path).open("rb"))
        ],
        # str, so a Windows drive in an absolute path survives the join with the native root
        build_scripts=[
            BuildScript(path=script, sha256=hashlib.sha256((root / str(script)).read_bytes()).hexdigest())
            for script in request.build_scripts
        ],
    )


def copyright_notice(root: Path, license_files: list[str]) -> str | None:
    # the first Copyright line of the license files the project names, as they sit in the project
    for license_file in license_files:
        if (path := root / license_file).is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("Copyright"):
                    return line
    return None


def wheel_request(wheel: Path, root: Path, settings: Settings, build_scripts: tuple[PurePosixPath, ...]) -> SbomRequest:
    with open_archive(wheel, str(wheel)) as archive:
        _, metadata = read_wheel_metadata(archive, str(wheel))
    return SbomRequest(
        root=root, metadata=metadata, wheel_name=wheel.name, settings=settings, build_scripts=build_scripts
    )


__all__ = [
    "copyright_notice",
    "read_source_tree",
    "wheel_request",
]
