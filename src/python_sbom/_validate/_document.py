from __future__ import annotations

from typing import TYPE_CHECKING, Final

from python_sbom import _core
from python_sbom.version import __version__

if TYPE_CHECKING:
    from typing import TypeIs  # new in 3.13; annotations here are never evaluated

    from python_sbom._model._types import Document

# the schema's uniqueItems compares every pair of items in an array, so a document whose components share one array
# takes about ten seconds to check at this count in Python; the cap stays so both implementations accept the same
MAX_COMPONENTS: Final[int] = _core.MAX_COMPONENTS


def validate_document(
    raw: str, allowed_licenses: frozenset[str] | None, max_components: int = MAX_COMPONENTS
) -> list[str]:
    allowed = None if allowed_licenses is None else sorted(allowed_licenses)
    return _core.validate_document(raw, allowed, max_components, __version__)


def _has(value: object, path: tuple[str, ...]) -> bool:
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    return True


def is_document(value: object) -> TypeIs[Document]:
    # what the SPDX rendering reads without a fallback; the schema leaves even these optional
    return isinstance(value, dict) and all(_has(value, ("metadata", "component", key)) for key in ("bom-ref", "name"))


__all__ = [
    "MAX_COMPONENTS",
    "is_document",
    "validate_document",
]
