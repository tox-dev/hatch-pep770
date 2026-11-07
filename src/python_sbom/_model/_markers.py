from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from packaging.requirements import Requirement


def applies_without_extras(requirement: Requirement | str) -> bool:
    # the conditions on extra are decided with no extra requested and every other condition stays unknown, so the
    # requirement applies unless its extra conditions alone rule it out
    return _core.applies_without_extras(str(requirement))


__all__ = [
    "applies_without_extras",
]
