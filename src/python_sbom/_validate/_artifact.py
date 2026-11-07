from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core
from python_sbom.version import __version__

from ._document import MAX_COMPONENTS

if TYPE_CHECKING:
    from pathlib import Path


def validate(path: Path, allowed_licenses: frozenset[str] | None, max_components: int = MAX_COMPONENTS) -> list[str]:
    # every top-level .dist-info counts, so a decoy one sorting first cannot hide the SBOM of another
    allowed = None if allowed_licenses is None else sorted(allowed_licenses)
    return _core.validate_artifact(path, allowed, max_components, __version__)


__all__ = [
    "validate",
]
