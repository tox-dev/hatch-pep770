from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from python_sbom._model._graph import reference_problems, shipped_libraries, walk_components

if TYPE_CHECKING:
    from python_sbom import Component, Dependency


def test_walk_visits_each_component_before_its_children_in_order() -> None:
    components: list[Component] = [
        {
            "type": "library",
            "bom-ref": "a",
            "name": "a",
            "components": [{"type": "file", "bom-ref": "a1", "name": "a1"}],
        },
        {"type": "library", "bom-ref": "b", "name": "b"},
    ]
    assert [component["bom-ref"] for component in walk_components(components)] == ["a", "a1", "b"]


def test_walk_survives_nesting_deeper_than_the_recursion_limit() -> None:
    root: Component = {"type": "library", "bom-ref": "0", "name": "0"}
    node = root
    for depth in range(1, 5000):
        child: Component = {"type": "library", "bom-ref": str(depth), "name": str(depth)}
        node["components"] = [child]
        node = child
    assert sum(1 for _ in walk_components([root])) == 5000


def test_shipped_libraries_skip_declared_requirements() -> None:
    hashed: Component = {"type": "library", "bom-ref": "hashed", "name": "x", "hashes": []}
    with_files: Component = {
        "type": "library",
        "bom-ref": "files",
        "name": "y",
        "components": [{"type": "file", "bom-ref": "f", "name": "f"}],
    }
    declared: Component = {"type": "library", "bom-ref": "declared", "name": "z"}
    assert [component["bom-ref"] for component in shipped_libraries([hashed, with_files, declared])] == [
        "hashed",
        "files",
    ]


@pytest.mark.parametrize(
    ("refs", "dependencies", "expected"),
    [
        pytest.param(["a", "b"], [{"ref": "a", "dependsOn": ["b"]}], [], id="valid"),
        pytest.param(["a", "a"], [], ["bom-ref values repeat: a"], id="repeated-ref"),
        pytest.param(
            ["a"],
            [{"ref": "a"}, {"ref": "a"}],
            ["dependencies list more than one entry for: a"],
            id="repeated-entry",
        ),
        pytest.param(
            ["a"],
            [{"ref": "a", "dependsOn": ["c", "b"]}],
            ["dependencies name bom-refs no component has: b, c"],
            id="unknown",
        ),
    ],
)
def test_reference_problems(refs: list[str], dependencies: list[Dependency], expected: list[str]) -> None:
    assert reference_problems(refs, dependencies) == expected
