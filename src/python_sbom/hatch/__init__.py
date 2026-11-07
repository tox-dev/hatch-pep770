"""The hatchling build hook: the backend that writes the SBOM while hatchling builds the wheel."""

from __future__ import annotations

from ._hook import SbomBuildHook

__all__ = [
    "SbomBuildHook",
]
