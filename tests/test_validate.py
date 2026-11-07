from __future__ import annotations

import json
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

from hatch_pep770.validate import document_problems, license_problems, wheel_problems

if TYPE_CHECKING:
    from pathlib import Path

    from hatch_pep770.cyclonedx import Component, Document, License

_ALLOWED: Final[frozenset[str]] = frozenset({"Apache-2.0", "BSD-3-Clause", "MIT"})


def _expression(expression: str) -> License:
    return {"expression": expression, "acknowledgement": "declared"}


def _named(name: str) -> License:
    return {"license": {"name": name, "acknowledgement": "declared"}}


def _concluded(identifier: str) -> License:
    return {"license": {"id": identifier, "acknowledgement": "concluded"}}


def _denied(expression: str, bom_ref: str = "pkg:pypi/example@1.0") -> str:
    return f"{bom_ref}: license {expression} is outside the allowed licenses ['Apache-2.0', 'BSD-3-Clause', 'MIT']"


def test_document_valid(sbom_document: Document) -> None:
    assert document_problems(json.dumps(sbom_document), _ALLOWED) == []


def test_document_schema_violation() -> None:
    problems: Final[list[str]] = document_problems(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "1"}), None
    )
    assert [problem.splitlines()[0] for problem in problems] == [
        "does not conform to the CycloneDX 1.6 schema: '1' is not of type 'integer'"
    ]


def test_document_serial_number_missing(sbom_document: Document) -> None:
    unnumbered: Final[dict[str, object]] = {key: value for key, value in sbom_document.items() if key != "serialNumber"}
    assert document_problems(json.dumps(unnumbered), None) == ["serialNumber must be a urn:uuid: RFC 4122 UUID, got ''"]


def test_document_duplicate_bom_ref(sbom_document: Document) -> None:
    sbom_document["components"][1]["bom-ref"] = sbom_document["components"][0]["bom-ref"]
    assert document_problems(json.dumps(sbom_document), None)[0] == (
        "bom-ref values are not unique: ['requires-dist:packaging>=24']"
    )


def test_document_dangling_dependency(sbom_document: Document) -> None:
    sbom_document["dependencies"].append({"ref": "pkg:pypi/example@1.0", "dependsOn": ["pkg:pypi/missing"]})
    problems: Final[list[str]] = document_problems(json.dumps(sbom_document), None)
    assert problems[0] == "dependencies reference bom-refs that do not exist: ['pkg:pypi/missing']"


def test_document_root_dependencies(sbom_document: Document) -> None:
    sbom_document["dependencies"][0]["dependsOn"] = ["requires-dist:packaging>=24"]
    assert document_problems(json.dumps(sbom_document), None) == [
        (
            "root dependsOn ['requires-dist:packaging>=24'] != components"
            " ['requires-dist:packaging>=24', \"requires-dist:tomli>=2; python_version < '3.11'\"]"
        )
    ]


def test_document_workflow_unknown_tool(sbom_document: Document) -> None:
    sbom_document["formulation"][0]["workflows"][0]["resourceReferences"].append({"ref": "tool:missing"})
    assert document_problems(json.dumps(sbom_document), None) == [
        "workflow wheel-build references unknown tools: ['tool:missing']"
    ]


def test_document_spdx_unparsable(sbom_document: Document) -> None:
    sbom_document["metadata"]["component"]["hashes"] = [{"alg": "BLAKE2b-256", "content": "0" * 64}]
    assert document_problems(json.dumps(sbom_document), None)[0].startswith("SPDX rendering does not parse:")


def test_document_spdx_invalid(sbom_document: Document) -> None:
    sbom_document["metadata"]["component"]["purl"] = "not a purl"
    assert document_problems(json.dumps(sbom_document), None)[0].startswith("SPDX rendering invalid:")


def test_wheel_without_sbom(tmp_path: Path) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "example-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("example-1.0.dist-info/METADATA", "Name: example\n")
    assert wheel_problems(wheel, None) == ["no .dist-info/sboms/*.cdx.json found in the wheel"]


def test_wheel_names_each_sbom(sbom_document: Document, tmp_path: Path) -> None:
    unnumbered: Final[dict[str, object]] = {key: value for key, value in sbom_document.items() if key != "serialNumber"}
    with zipfile.ZipFile(wheel := tmp_path / "example-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("example-1.0.dist-info/sboms/example.cdx.json", json.dumps(unnumbered))
    assert wheel_problems(wheel, None) == [
        "example-1.0.dist-info/sboms/example.cdx.json: serialNumber must be a urn:uuid: RFC 4122 UUID, got ''"
    ]


@pytest.mark.parametrize(
    ("licenses", "expected"),
    [
        pytest.param([_expression("MIT")], [], id="allowed"),
        pytest.param([_expression("mit")], [], id="allowed-any-case"),
        pytest.param([_expression("GPL-3.0-only")], [_denied("GPL-3.0-only")], id="denied"),
        pytest.param([_expression("Apache-2.0 OR GPL-3.0-only")], [], id="or-one-allowed"),
        pytest.param(
            [_expression("GPL-3.0-only OR MPL-2.0")], [_denied("GPL-3.0-only OR MPL-2.0")], id="or-none-allowed"
        ),
        pytest.param([_expression("MIT AND BSD-3-Clause")], [], id="and-all-allowed"),
        pytest.param([_expression("MIT AND GPL-3.0-only")], [_denied("MIT AND GPL-3.0-only")], id="and-one-denied"),
        pytest.param([_expression("MIT OR GPL-3.0-only AND LGPL-3.0-only")], [], id="and-binds-tighter"),
        pytest.param(
            [_expression("(MIT OR GPL-3.0-only) AND LGPL-3.0-only")],
            [_denied("(MIT OR GPL-3.0-only) AND LGPL-3.0-only")],
            id="parentheses",
        ),
        pytest.param([_expression("Apache-2.0 WITH LLVM-exception")], [], id="with-allowed"),
        pytest.param(
            [_expression("GPL-2.0-only WITH Classpath-exception-2.0")],
            [_denied("GPL-2.0-only WITH Classpath-exception-2.0")],
            id="with-denied",
        ),
        pytest.param([_named("MIT License"), _concluded("MIT")], [], id="concluded-allowed"),
        pytest.param([_named("MPL 2.0"), _concluded("MPL-2.0")], [_denied("MPL-2.0")], id="concluded-denied"),
        pytest.param(
            [_concluded("MIT"), _concluded("LGPL-3.0-only")], [_denied("LGPL-3.0-only")], id="concluded-all-apply"
        ),
        pytest.param(
            [_named("MIT License")],
            ["pkg:pypi/example@1.0: declares license names ['MIT License'] with no SPDX id"],
            id="name-only",
        ),
        pytest.param([], ["pkg:pypi/example@1.0: declares no license"], id="undeclared"),
    ],
)
def test_license_policy(licenses: list[License], expected: list[str]) -> None:
    component: Final[Component] = {
        "type": "library",
        "bom-ref": "pkg:pypi/example@1.0",
        "name": "example",
        "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
        "licenses": licenses,
    }
    assert license_problems([component], _ALLOWED) == expected


@pytest.mark.parametrize(
    ("expression", "reason"),
    [
        pytest.param("MIT AND", "it ends early", id="trailing-operator"),
        pytest.param("OR MIT", "unexpected 'OR'", id="leading-operator"),
        pytest.param("(MIT", "it ends early", id="unclosed"),
        pytest.param("MIT)", "unexpected ')'", id="unopened"),
        pytest.param("(MIT Apache-2.0)", "expected ')', got 'Apache-2.0'", id="missing-operator"),
        pytest.param("MIT and Apache-2.0", "unexpected 'and'", id="lower-case-operator"),
        pytest.param("Apache-2.0 WITH OR", "unexpected 'OR'", id="with-operator"),
    ],
)
def test_license_policy_malformed(expression: str, reason: str) -> None:
    component: Final[Component] = {
        "type": "library",
        "bom-ref": "pkg:pypi/example@1.0",
        "name": "example",
        "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
        "licenses": [_expression(expression)],
    }
    assert license_problems([component], _ALLOWED) == [
        f"pkg:pypi/example@1.0: license expression {expression!r} is malformed: {reason}"
    ]


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            {"type": "library", "bom-ref": "requires-dist:distlib", "name": "distlib"}, id="declared-requirement"
        ),
        pytest.param(
            {
                "type": "library",
                "bom-ref": "pkg:pypi/pip@1.0",
                "name": "pip",
                "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
                "licenses": [_expression("MIT")],
                "components": [
                    {"type": "library", "bom-ref": "pkg:pypi/pip@1.0#vendored/pkg:pypi/autocommand@2.2.2", "name": "a"},
                ],
            },
            id="vendored-by-bundled-wheel",
        ),
        pytest.param(
            {
                "type": "file",
                "bom-ref": "loader",
                "name": "loader",
                "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
            },
            id="file",
        ),
    ],
)
def test_license_policy_skips_unshipped(component: Component) -> None:
    assert license_problems([component], _ALLOWED) == []


def test_license_policy_judges_files_owner() -> None:
    component: Final[Component] = {
        "type": "library",
        "bom-ref": "pkg:pypi/distlib@0.4",
        "name": "distlib",
        "licenses": [_concluded("LGPL-3.0-only")],
        "components": [{"type": "file", "bom-ref": "pkg:pypi/distlib@0.4#distlib/__init__.py", "name": "x"}],
    }
    assert license_problems([component], _ALLOWED) == [_denied("LGPL-3.0-only", "pkg:pypi/distlib@0.4")]
