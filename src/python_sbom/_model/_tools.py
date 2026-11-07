from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from ._inputs import BuildFacts
    from ._types import Component, Dependency


def tool_components(facts: BuildFacts) -> tuple[list[Component], list[Dependency]]:
    return _core.tool_components(facts)


__all__ = [
    "tool_components",
]
