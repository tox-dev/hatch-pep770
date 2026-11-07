from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final, TypeAlias

import pytest

from python_sbom._formats._json import dumps
from python_sbom._validate._document import is_document, validate_document

if TYPE_CHECKING:
    from collections.abc import Callable

    from conftest import Describe
    from pytest_mock import MockerFixture

    from python_sbom import Component, License
    from python_sbom._model._types import Document

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"
# what auditwheel writes: CycloneDX 1.4 conventions, a legacy tools array, no timestamp
_FOREIGN: Final[str] = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "component": {"type": "library", "bom-ref": "pkg:pypi/plain@1.0", "name": "plain", "version": "1.0"},
        "tools": [{"name": "auditwheel", "version": "6.4.0"}],
    },
    "components": [{"type": "library", "bom-ref": "pkg:rpm/almalinux/libfoo@1", "name": "libfoo", "version": "1"}],
    "dependencies": [{"ref": "pkg:pypi/plain@1.0", "dependsOn": ["pkg:rpm/almalinux/libfoo@1"]}],
})


def test_valid(describe: Describe) -> None:
    assert validate_document(dumps(describe("Requires-Dist: click\nLicense-Expression: MIT\n")).decode(), None) == []


def test_not_json() -> None:
    assert validate_document("this is not json", None) == ["is not JSON: Expecting value: line 1 column 1 (char 0)"]


def test_schema_violation() -> None:
    (problem,) = validate_document(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "one"}), None)
    assert problem == "does not conform to the CycloneDX 1.6 schema: 'one' is not of type 'integer' at $.version"


def test_other_tools_documents_get_the_schema_check_alone() -> None:
    assert validate_document(_FOREIGN, None) == []


def test_oversized_document_is_not_parsed() -> None:
    assert validate_document(" " * (16 * 1024 * 1024 + 1), None) == [
        "is 16777217 characters long, over the 16777216 character limit"
    ]


def test_component_cap_counts_nested_components() -> None:
    assert validate_document(many_components(), None) == [
        "lists more than 5000 components, nested ones included; pass a higher --max-components to check it"
    ]


def many_components() -> str:
    # 100 groups of 50 parts, 5,100 components in all, yet no array long enough to slow the schema check
    groups = [
        {
            "type": "library",
            "name": f"group-{group}",
            "components": [{"type": "library", "name": f"part-{part}"} for part in range(50)],
        }
        for group in range(100)
    ]
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": groups})


def test_component_cap_can_be_raised() -> None:
    assert validate_document(many_components(), None, max_components=5_100) == []


def test_missing_fields(describe: Describe) -> None:
    # the schema makes the timestamp optional, so the loaded JSON, not the typed document, loses it
    loaded = json.loads(dumps(describe()))
    del loaded["metadata"]["timestamp"]
    assert validate_document(json.dumps(loaded), None) == [
        "lacks metadata.timestamp, which every document python-sbom writes carries"
    ]


def test_serial_is_required(describe: Describe) -> None:
    # the schema makes it optional, so the loaded JSON, not the typed document, loses it
    loaded = json.loads(dumps(describe()))
    del loaded["serialNumber"]
    assert validate_document(json.dumps(loaded), None) == ["serialNumber must be a urn:uuid: RFC 4122 UUID, got ''"]


def test_duplicate_refs(describe: Describe) -> None:
    library: Component = {"type": "library", "bom-ref": "pkg:pypi/example@1.0", "name": "copy"}
    assert validate_document(with_components(describe(), library), None) == [
        "bom-ref values are not unique: ['pkg:pypi/example@1.0']"
    ]


def with_components(document: Document, *components: Component) -> str:
    document["components"].extend(components)
    document["dependencies"][0].setdefault("dependsOn", []).extend(component["bom-ref"] for component in components)
    return dumps(document).decode()


def test_duplicate_refs_in_other_tools_documents() -> None:
    foreign = json.loads(_FOREIGN)
    foreign["components"].append({"type": "library", "bom-ref": "pkg:pypi/plain@1.0", "name": "copy"})
    assert validate_document(json.dumps(foreign), None) == ["bom-ref values are not unique: ['pkg:pypi/plain@1.0']"]


def test_component_without_bom_ref(describe: Describe) -> None:
    # the schema makes the bom-ref optional, so the loaded JSON, not the typed document, loses it
    loaded = json.loads(dumps(describe()))
    loaded["components"].append({"type": "library", "name": "nameless"})
    assert validate_document(json.dumps(loaded), None) == ["components lack a bom-ref: ['nameless']"]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda loaded: loaded["formulation"][0]["workflows"][0].pop("resourceReferences"),
            id="workflow-without-resources",
        ),
        pytest.param(
            lambda loaded: loaded["formulation"][0]["workflows"][0]["resourceReferences"].append({
                "externalReference": {"type": "other", "url": "https://example.org"}
            }),
            id="workflow-external-resource",
        ),
        pytest.param(
            lambda loaded: loaded["metadata"]["properties"].append({"name": "example:extra"}),
            id="property-without-value",
        ),
        pytest.param(
            lambda loaded: loaded["metadata"]["component"]["properties"].append({"name": "example:extra"}),
            id="root-property-without-value",
        ),
        pytest.param(
            lambda loaded: loaded["metadata"].update(supplier={"url": ["https://example.org"]}),
            id="supplier-without-name",
        ),
    ],
)
def test_schema_valid_variations_pass(describe: Describe, mutate: Callable[[dict[str, _Json]], None]) -> None:
    loaded = json.loads(dumps(describe()))
    mutate(loaded)
    assert validate_document(json.dumps(loaded), None) == []


def test_unknown_dependency_refs(describe: Describe) -> None:
    document = describe()
    document["dependencies"].append({"ref": "ghost", "dependsOn": ["phantom"]})
    assert validate_document(dumps(document).decode(), None) == [
        "dependencies reference bom-refs that do not exist: ['ghost', 'phantom']"
    ]


def test_root_must_depend_on_components(describe: Describe) -> None:
    document = describe("Requires-Dist: click\n")
    document["dependencies"][0]["dependsOn"] = []
    assert validate_document(dumps(document).decode(), None) == [
        "root dependsOn [] != components ['requires-dist:click']"
    ]


def test_workflow_must_reference_tools(describe: Describe) -> None:
    document = describe()
    document.get("formulation", [])[0]["workflows"][0]["resourceReferences"].append({"ref": "pkg:pypi/example@1.0"})
    assert validate_document(dumps(document).decode(), None) == [
        "workflow wheel-build references unknown tools: ['pkg:pypi/example@1.0']"
    ]


def test_formula_without_workflows(describe: Describe) -> None:
    loaded = json.loads(dumps(describe()))
    loaded["formulation"] = [{"bom-ref": "formula:other"}]
    assert validate_document(json.dumps(loaded), None) == []


def test_spdx_rendering_must_validate(describe: Describe) -> None:
    document = describe()
    properties = document["metadata"].get("properties", [])
    properties.append({"name": "example:sbom:repository", "value": "https://example.org/a#fragment"})
    (problem,) = validate_document(dumps(document).decode(), None)
    assert problem.startswith("SPDX rendering invalid: ")


def test_spdx_rendering_must_parse(describe: Describe) -> None:
    raw = with_components(describe(), shipped([{"expression": "MIT AND", "acknowledgement": "declared"}]))
    assert any(problem.startswith("SPDX rendering does not parse: ") for problem in validate_document(raw, None))


def shipped(licenses: list[License]) -> Component:
    return {
        "type": "library",
        "bom-ref": "bundled:lib.whl",
        "name": "lib",
        "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
        "licenses": licenses,
    }


def test_deep_nesting_is_reported(describe: Describe) -> None:
    nested = "".join(
        f'{{"type": "library", "bom-ref": "deep-{level}", "name": "deep", "components": [' for level in range(500)
    )
    nested += "]}" * 500
    raw = json.dumps(describe()).replace('"components": []', f'"components": [{nested}]', 1)
    assert validate_document(raw, None) == [
        "does not conform to the CycloneDX 1.6 schema: it nests too deeply to check"
    ]


def test_license_policy(describe: Describe) -> None:
    raw = with_components(describe(), shipped([{"expression": "MIT AND GPL-3.0-only"}]))
    assert validate_document(raw, frozenset({"MIT"})) == [
        "bundled:lib.whl: license MIT AND GPL-3.0-only is outside the allowed licenses ['MIT']"
    ]


def test_unexpected_error_is_reported(describe: Describe, mocker: MockerFixture) -> None:
    mocker.patch("python_sbom._validate._document.render_spdx", autospec=True, side_effect=RuntimeError("x" * 300))
    assert validate_document(dumps(describe()).decode(), None) == [f"could not be checked, RuntimeError: {'x' * 200}"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(json.loads(_FOREIGN), True, id="foreign"),
        pytest.param({"metadata": {"component": {"name": "plain"}}}, False, id="root-without-bom-ref"),
        pytest.param({"metadata": {"component": {"bom-ref": "plain"}}}, False, id="root-without-name"),
        pytest.param({"metadata": {}}, False, id="no-root"),
        pytest.param([], False, id="not-an-object"),
    ],
)
def test_is_document(value: _Json, expected: bool) -> None:
    assert is_document(value) is expected
