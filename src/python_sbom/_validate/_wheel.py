from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

from python_sbom._wheel._archive import find_dist_info

from ._document import validate

if TYPE_CHECKING:
    from pathlib import Path


def validate_wheel(wheel: Path, allowed_licenses: frozenset[str] | None) -> list[str]:
    """
    Check every CycloneDX SBOM a wheel carries under ``.dist-info/sboms/``; needs the ``validate`` extra.

    :param wheel: the wheel to read
    :param allowed_licenses: SPDX license ids the shipped components may use, or ``None`` to skip the license policy
    :returns: one message per problem, empty when the wheel carries at least one SBOM and every SBOM is valid
    :raises MissingExtraError: when the ``validate`` extra is not installed

    """
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        prefix = f"{find_dist_info(names)}/sboms/"
        sboms = {
            name: archive.read(name).decode("utf-8")
            for name in sorted(names)
            if name.startswith(prefix) and name.endswith(".cdx.json")
        }
    if not sboms:
        return ["no .dist-info/sboms/*.cdx.json found in the wheel"]
    return [f"{name}: {problem}" for name, raw in sboms.items() for problem in validate(raw, allowed_licenses)]


__all__ = [
    "validate_wheel",
]
