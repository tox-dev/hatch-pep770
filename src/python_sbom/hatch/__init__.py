"""The hatchling build hook, which writes the SBOM into every wheel hatchling builds."""

from __future__ import annotations

from ._hook import SbomBuildHook

__all__ = [
    "SbomBuildHook",
]
