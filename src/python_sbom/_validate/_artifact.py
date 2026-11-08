from __future__ import annotations

import zipfile
from typing import IO, TYPE_CHECKING, Final

from python_sbom._wheel._zip import CHUNK, open_archive

from ._document import validate_document
from ._limits import MAX_COMPONENTS, byte_limit

if TYPE_CHECKING:
    from pathlib import Path


def validate(path: Path, allowed_licenses: frozenset[str] | None, max_components: int = MAX_COMPONENTS) -> list[str]:
    limit: Final[int] = byte_limit(max_components)
    if not zipfile.is_zipfile(path):
        with path.open("rb") as file:
            return validate_document(_read(file, limit), allowed_licenses, max_components)
    problems: Final[list[str]] = []
    with open_archive(path, path.name) as archive:
        if not (names := sorted(name for name in archive.namelist() if _is_sbom(name))):
            return [f"no SBOM found in {path.name}"]
        # one at a time, so memory holds a single SBOM however many the archive packs
        for name in names:
            with archive.open(name) as member:
                raw = _read(member, limit)
            problems.extend(
                f"{name}: {problem}" for problem in validate_document(raw, allowed_licenses, max_components)
            )
    return problems


def _read(source: IO[bytes], limit: int) -> bytes:
    # stops within a chunk past the limit: enough for validate_document to refuse the SBOM without reading all of it
    content: Final[bytearray] = bytearray()
    while len(content) <= limit and (chunk := source.read(CHUNK)):
        content.extend(chunk)
    return bytes(content)


def _is_sbom(name: str) -> bool:
    # every top-level .dist-info counts, so a decoy one sorting first cannot hide the SBOM of another
    match name.split("/"):
        case [file]:
            return file.endswith(".cdx.json")
        case [dist_info, "sboms", file]:
            return dist_info.endswith(".dist-info") and file.endswith(".cdx.json")
        case _:
            return False


__all__ = [
    "validate",
]
