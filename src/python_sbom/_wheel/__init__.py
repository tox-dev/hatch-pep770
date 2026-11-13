"""Zip artifacts: one checked handle per build, verifying the wheels they bundle, and writing an SBOM in."""

from __future__ import annotations

from ._sdist import add_to_sdist

__all__ = [
    "add_to_sdist",
]
