from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import dumps, validate

if TYPE_CHECKING:
    from conftest import Describe

    from python_sbom import Component, Document, License

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
_ALLOWED: Final[frozenset[str]] = frozenset({"MIT", "BSD-3-Clause", "GPL-2.0-only"})


def test_valid(describe: Describe) -> None:
    assert validate(dumps(describe("Requires-Dist: click\nLicense-Expression: MIT\n")).decode(), None) == []


def test_schema_violation() -> None:
    (problem,) = validate(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "one"}), None)
    assert problem.startswith("does not conform to the CycloneDX 1.6 schema: ")


def test_other_tools_documents_get_the_schema_check_alone() -> None:
    assert validate(_FOREIGN, None) == []


def test_missing_fields(describe: Describe) -> None:
    # the schema makes the timestamp optional, so the loaded JSON, not the typed document, loses it
    loaded = json.loads(dumps(describe()))
    del loaded["metadata"]["timestamp"]
    assert validate(json.dumps(loaded), None) == [
        "lacks metadata.timestamp, which every document python-sbom writes carries"
    ]


def test_serial_is_required(describe: Describe) -> None:
    # the schema makes it optional, so the loaded JSON, not the typed document, loses it
    loaded = json.loads(dumps(describe()))
    del loaded["serialNumber"]
    assert validate(json.dumps(loaded), None) == ["serialNumber must be a urn:uuid: RFC 4122 UUID, got ''"]


def test_duplicate_refs(describe: Describe) -> None:
    library: Component = {"type": "library", "bom-ref": "pkg:pypi/example@1.0", "name": "copy"}
    assert validate(with_components(describe(), library), None) == [
        "bom-ref values are not unique: ['pkg:pypi/example@1.0']"
    ]


def with_components(document: Document, *components: Component) -> str:
    document["components"].extend(components)
    document["dependencies"][0].setdefault("dependsOn", []).extend(component["bom-ref"] for component in components)
    return dumps(document).decode()


def test_unknown_dependency_refs(describe: Describe) -> None:
    document = describe()
    document["dependencies"].append({"ref": "ghost", "dependsOn": ["phantom"]})
    assert validate(dumps(document).decode(), None) == [
        "dependencies reference bom-refs that do not exist: ['ghost', 'phantom']"
    ]


def test_root_must_depend_on_components(describe: Describe) -> None:
    document = describe("Requires-Dist: click\n")
    document["dependencies"][0]["dependsOn"] = []
    assert validate(dumps(document).decode(), None) == ["root dependsOn [] != components ['requires-dist:click']"]


def test_workflow_must_reference_tools(describe: Describe) -> None:
    document = describe()
    document.get("formulation", [])[0]["workflows"][0]["resourceReferences"].append({"ref": "pkg:pypi/example@1.0"})
    assert validate(dumps(document).decode(), None) == [
        "workflow wheel-build references unknown tools: ['pkg:pypi/example@1.0']"
    ]


def test_formula_without_workflows(describe: Describe) -> None:
    loaded = json.loads(dumps(describe()))
    loaded["formulation"] = [{"bom-ref": "formula:other"}]
    assert validate(json.dumps(loaded), None) == []


def test_spdx_rendering_must_validate(describe: Describe) -> None:
    document = describe()
    properties = document["metadata"].get("properties", [])
    properties.append({"name": "example:sbom:repository", "value": "https://example.org/a#fragment"})
    (problem,) = validate(dumps(document).decode(), None)
    assert problem.startswith("SPDX rendering invalid: ")


def test_spdx_rendering_must_parse(describe: Describe) -> None:
    raw = with_components(describe(), shipped("broken", [{"expression": "MIT AND", "acknowledgement": "declared"}]))
    assert any(problem.startswith("SPDX rendering does not parse: ") for problem in validate(raw, None))


def shipped(name: str, licenses: list[License]) -> Component:
    return {
        "type": "library",
        "bom-ref": f"bundled:{name}.whl",
        "name": name,
        "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
        "licenses": licenses,
    }


def test_deep_nesting_is_reported(describe: Describe) -> None:
    nested = '{"type": "library", "bom-ref": "deep", "name": "deep", "components": [' * 500 + "]}" * 500
    raw = json.dumps(describe()).replace('"components": []', f'"components": [{nested}]', 1)
    assert validate(raw, None) == ["does not conform to the CycloneDX 1.6 schema: it nests too deeply to check"]


@pytest.mark.parametrize(
    "licenses",
    [
        pytest.param([{"expression": "MIT"}], id="expression"),
        pytest.param([{"license": {"id": "mit", "acknowledgement": "concluded"}}], id="id-case-insensitive"),
        pytest.param([{"expression": "MIT OR GPL-3.0-only"}], id="any-of"),
        pytest.param([{"expression": "(GPL-3.0-only OR MIT) AND BSD-3-Clause"}], id="grouped"),
        pytest.param([{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}], id="exception"),
    ],
)
def test_license_policy_allows(describe: Describe, licenses: list[License]) -> None:
    problems = validate(with_components(describe(), shipped("lib", licenses)), _ALLOWED)
    assert [problem for problem in problems if problem.startswith("bundled:lib.whl")] == []


@pytest.mark.parametrize(
    ("licenses", "problem"),
    [
        pytest.param(
            [{"expression": "MIT AND GPL-3.0-only"}],
            "license MIT AND GPL-3.0-only is outside the allowed licenses ['BSD-3-Clause', 'GPL-2.0-only', 'MIT']",
            id="denied",
        ),
        pytest.param(
            [{"license": {"name": "BSD License", "acknowledgement": "declared"}}],
            "declares license names ['BSD License'] with no SPDX id",
            id="names",
        ),
        pytest.param([], "declares no license", id="none"),
        pytest.param([{"expression": "MIT AND"}], "license expression 'MIT AND' is malformed: it ends early", id="end"),
        pytest.param([{"expression": "(MIT"}], "license expression '(MIT' is malformed: it ends early", id="open"),
        pytest.param(
            [{"expression": "(MIT ISC)"}],
            "license expression '(MIT ISC)' is malformed: expected ')', got 'ISC'",
            id="pair",
        ),
        pytest.param([{"expression": "MIT)"}], "license expression 'MIT)' is malformed: unexpected ')'", id="close"),
        pytest.param(
            [{"expression": "AND MIT"}], "license expression 'AND MIT' is malformed: unexpected 'AND'", id="op"
        ),
        pytest.param(
            [{"expression": "MIT WITH OR"}], "license expression 'MIT WITH OR' is malformed: unexpected 'OR'", id="with"
        ),
    ],
)
def test_license_policy_reports(describe: Describe, licenses: list[License], problem: str) -> None:
    problems = validate(with_components(describe(), shipped("lib", licenses)), _ALLOWED)
    assert f"bundled:lib.whl: {problem}" in problems


def test_license_policy_judges_only_shipped_components(describe: Describe) -> None:
    declared: Component = {"type": "library", "bom-ref": "requires-dist:click", "name": "click"}
    vendored: Component = {"type": "library", "bom-ref": "bundled:outer.whl#vendored", "name": "vendored"}
    outer = shipped("outer", [{"expression": "MIT"}])
    outer["components"] = [vendored, {"type": "file", "bom-ref": "outer#a.py", "name": "a.py"}]
    assert validate(with_components(describe(), declared, outer), frozenset({"MIT"})) == []
