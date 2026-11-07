from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from python_sbom._model._types import Component


def license_problems(components: list[Component], allowed: frozenset[str]) -> list[str]:
    # only what the artifact carries bytes for is judged: a declared requirement resolves at install time, and a library
    # a bundled wheel vendors ships under that wheel's terms
    return _core.license_problems(components, sorted(allowed))


__all__ = [
    "license_problems",
]
