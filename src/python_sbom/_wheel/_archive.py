from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from pathlib import Path


def write_sbom(wheel: Path, name: str, content: bytes, epoch: int) -> str:
    # the other members keep their bytes as stored, still compressed, so only the SBOM and RECORD get compressed here;
    # both go last, RECORD after the SBOM, and the result replaces the wheel only once fully written
    return _core.write_sbom(wheel, name, content, epoch)


__all__ = [
    "write_sbom",
]
