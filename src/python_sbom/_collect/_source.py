from __future__ import annotations

from pathlib import PurePath
from typing import TYPE_CHECKING, Final

from python_sbom import SbomError
from python_sbom._model._inputs import BuildScript
from python_sbom._wheel._zip import sha256_hex

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path, PurePosixPath

    from python_sbom._model._inputs import Settings


def copyright_notice(root: Path, license_files: list[str]) -> str | None:
    # the first Copyright line of the license files the project names, as they sit in the project
    for license_file in license_files:
        if (path := root / license_file).is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("Copyright"):
                    return line
    return None


def selected_wheels(root: Path, settings: Settings) -> list[str]:
    wheels: Final[set[str]] = set()
    for pattern in settings.bundled_wheels:
        # a wheel outside the project is none the project ships, and pathlib refuses an absolute pattern outright
        if (path := PurePath(pattern)).anchor or ".." in path.parts:
            msg = f"`bundled-wheels` pattern {pattern!r} must be relative to the project, without `..`"
            raise SbomError(msg)
        wheels.update(wheel.relative_to(root).as_posix() for wheel in root.glob(pattern))
    return sorted(wheels)


def hash_build_scripts(root: Path, paths: Iterable[PurePosixPath]) -> list[BuildScript]:
    # str, so a Windows drive in an absolute path survives the join with the native root; a script named twice, by the
    # caller and by the provider, is listed once
    return [BuildScript(path=path, sha256=file_sha256(root / str(path))) for path in dict.fromkeys(paths)]


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return sha256_hex(stream)


__all__ = [
    "copyright_notice",
    "file_sha256",
    "hash_build_scripts",
    "selected_wheels",
]
