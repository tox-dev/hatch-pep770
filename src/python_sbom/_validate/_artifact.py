from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING, Final

from python_sbom._wheel._archive import open_archive, read_member

from ._document import MAX_COMPONENTS, validate_document

if TYPE_CHECKING:
    from pathlib import Path

# an SBOM lists every file of its wheel at a few hundred bytes each, so even a wheel with a hundred thousand files stays
# well under this, while one archive member can make validation hold no more than this in memory
_SBOM_LIMIT: Final[int] = 64 * 1024 * 1024


def validate(path: Path, allowed_licenses: frozenset[str] | None, max_components: int = MAX_COMPONENTS) -> list[str]:
    if not zipfile.is_zipfile(path):
        return validate_document(path.read_text(encoding="utf-8"), allowed_licenses, max_components)
    with open_archive(path, path.name) as archive:
        found: Final[dict[str, str]] = {
            name: read_member(archive, name, path.name, _SBOM_LIMIT).decode("utf-8")
            for name in sorted(archive.namelist())
            if _is_sbom(name)
        }
    if not found:
        return [f"no SBOM found in {path.name}"]
    return [
        f"{name}: {problem}"
        for name, raw in found.items()
        for problem in validate_document(raw, allowed_licenses, max_components)
    ]


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
