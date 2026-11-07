from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from ._types import Component, Dependency


def artifact_contents(root: Component, components: list[Component]) -> list[Component]:
    # what the artifact holds or declares, wherever the document places it: the files and wheels nested under the root,
    # which sit in an archive's top level, and the components; not the root itself, nor the tools that built it, so
    # generation, the license policy and validation all judge the same set
    return [*root.get("components", []), *components]


def shipped_libraries(contents: list[Component]) -> list[Component]:
    # what the artifact carries bytes for: a declared requirement resolves at install time, and a library a bundled
    # wheel vendors ships under that wheel's terms
    return [
        component
        for component in walk_components(contents)
        if component["type"] == "library"
        and ("hashes" in component or any(child["type"] == "file" for child in component.get("components", [])))
    ]


def walk_components(components: Iterable[Component]) -> Iterator[Component]:
    # depth first, each component before the ones it nests, in document order; iterative, so a deeply nested document
    # cannot exhaust the stack
    pending: Final[list[Component]] = list(reversed(list(components)))
    while pending:
        component = pending.pop()
        yield component
        pending.extend(reversed(component.get("components", [])))


def reference_problems(refs: list[str], dependencies: list[Dependency]) -> list[str]:
    # what generation refuses and validation reports alike: a bom-ref given twice, which formulas and workflows share
    # with components; a second dependency entry for one ref, which a reader taking them as a mapping would let a valid
    # entry hide an invalid one with, while the SPDX rendering keeps the edges of both; and an entry naming no component
    if twice := repeated(refs):
        return [f"bom-ref values repeat: {', '.join(twice)}"]
    if twice := repeated(entry["ref"] for entry in dependencies):
        return [f"dependencies list more than one entry for: {', '.join(twice)}"]
    named: Final[set[str]] = {ref for entry in dependencies for ref in (entry["ref"], *entry.get("dependsOn", []))}
    if unknown := sorted(named - set(refs)):
        return [f"dependencies name bom-refs no component has: {', '.join(unknown)}"]
    return []


def repeated(values: Iterable[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


__all__ = [
    "artifact_contents",
    "reference_problems",
    "repeated",
    "shipped_libraries",
    "walk_components",
]
