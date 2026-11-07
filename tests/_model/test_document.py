from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, cast

import pytest

from python_sbom import ContentProvider, Contributions
from python_sbom._errors import SbomError
from python_sbom._model._document import checked_contributions, contributed_properties, formulation, with_header

if TYPE_CHECKING:
    from python_sbom import Component, Dependency, Property
    from python_sbom._model._inputs import BuildFacts
    from python_sbom._model._types import Body, Formula


def test_document_serial_derives_from_body() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [],
    }
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "https://example.org/sboms")
    assert with_header(body, namespace) == {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }


def test_header_refuses_repeated_refs() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "bom-ref": "app", "name": "tool"}]},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [],
    }
    with pytest.raises(SbomError, match="bom-ref values repeat: app"):
        with_header(body, uuid.uuid4())


def test_header_refuses_unknown_dependency() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [{"ref": "app", "dependsOn": ["ghost"]}],
    }
    with pytest.raises(SbomError, match="dependencies name bom-refs no component has: ghost"):
        with_header(body, uuid.uuid4())


def test_contributed_properties_keep_their_own_prefix() -> None:
    properties: list[Property] = [{"name": "extra:key", "value": "1"}]
    assert contributed_properties(properties, "example") == properties


def test_contributed_properties_refuse_the_project_prefix() -> None:
    with pytest.raises(SbomError, match="example:vcs-commit use the example: prefix python-sbom writes"):
        contributed_properties([{"name": "example:vcs-commit", "value": "0"}], "example")


def _partial(**fields: str | list[dict[str, str]]) -> Component:
    # a component a provider got wrong, which the types alone would not let through
    return cast("Component", fields)


def test_header_refuses_a_second_dependency_entry_for_a_ref() -> None:
    # as when a provider adds an entry for the root, whose entry python-sbom writes
    body = _body([], [{"ref": "app", "dependsOn": []}, {"ref": "app", "dependsOn": []}], [])
    with pytest.raises(SbomError, match="dependencies list more than one entry for: app"):
        with_header(body, uuid.uuid4())


def _body(components: list[Component], dependencies: list[Dependency], formulation: list[Formula]) -> Body:
    return {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": components,
        "dependencies": dependencies,
        "formulation": formulation,
    }


@pytest.mark.parametrize(
    "ref", [pytest.param("formula:build", id="formula"), pytest.param("workflow:build", id="workflow")]
)
def test_header_refuses_a_component_taking_a_formulation_ref(facts: BuildFacts, ref: str) -> None:
    formula = formulation("build", "build the app", [], "app", facts)
    body = _body([{"type": "library", "bom-ref": ref, "name": "clash"}], [], [formula])
    with pytest.raises(SbomError, match=f"bom-ref values repeat: {ref}"):
        with_header(body, uuid.uuid4())


@pytest.mark.parametrize(
    ("contributions", "missing"),
    [
        pytest.param(Contributions(components=[_partial(type="library", name="zlib")]), "bom-ref", id="component"),
        pytest.param(
            Contributions(
                components=[
                    _partial(type="library", name="zlib", **{"bom-ref": "zlib", "components": [{"type": "file"}]})
                ]
            ),
            "bom-ref, name",
            id="nested",
        ),
        pytest.param(Contributions(tools=[_partial(name="cmake", **{"bom-ref": "tool:cmake"})]), "type", id="tool"),
    ],
)
def test_contributions_need_the_fields_the_build_reads(contributions: Contributions, missing: str) -> None:
    with pytest.raises(SbomError, match=f"content provider ContentProvider added a component without {missing}: "):
        checked_contributions(contributions, ContentProvider())


def test_complete_contributions_pass() -> None:
    contributions = Contributions(components=[{"type": "library", "bom-ref": "zlib", "name": "zlib"}])
    assert checked_contributions(contributions, ContentProvider()) is contributions
