from __future__ import annotations

import dataclasses
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, TypeAlias

import pytest

from python_sbom._formats._json import dumps
from python_sbom._formats._spdx import render_spdx, to_spdx
from python_sbom._validate._schemas import spdx_problems
from python_sbom.version import __version__

if TYPE_CHECKING:
    from conftest import Describe

    from python_sbom import Component
    from python_sbom._formats._spdx import _Package
    from python_sbom._model._inputs import Settings

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"

# what auditwheel writes: CycloneDX 1.4 conventions, a legacy tools array, no timestamp and no serial number
_FOREIGN: Final[str] = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "component": {"type": "library", "bom-ref": "pkg:pypi/plain@1.0", "name": "plain", "version": "1.0"},
        "tools": [{"name": "auditwheel", "version": "6.4.0"}, {"name": "repair"}, {"vendor": "PyPA"}],
    },
    "components": [{"type": "library", "bom-ref": "pkg:rpm/almalinux/libfoo@1", "name": "libfoo", "version": "1"}],
    "dependencies": [{"ref": "pkg:pypi/plain@1.0", "dependsOn": ["pkg:rpm/almalinux/libfoo@1"]}],
})


def test_minimal(describe: Describe) -> None:
    document = describe()
    spdx = render_spdx(document)
    ids = {package["name"]: package["SPDXID"] for package in spdx["packages"]}
    serial = document["serialNumber"]
    assert spdx == {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Example-1.0",
        "documentNamespace": f"https://spdx.org/spdxdocs/sboms/Example-1.0-{serial.removeprefix('urn:uuid:')}",
        "comment": f"Rendered from the CycloneDX SBOM {serial} (example.cdx.json), which also carries per-file hashes"
        " and the build formulation.",
        "creationInfo": {"created": "2023-11-14T22:13:20Z", "creators": [f"Tool: python-sbom-{__version__}"]},
        "packages": [
            {
                "SPDXID": ids["Example"],
                "name": "Example",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "primaryPackagePurpose": "APPLICATION",
                "versionInfo": "1.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/example@1.0",
                    }
                ],
            },
            {
                "SPDXID": ids["cpython"],
                "name": "cpython",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "primaryPackagePurpose": "OTHER",
                "versionInfo": "3.15.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:generic/cpython@3.15.0",
                    }
                ],
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": ids["Example"],
            },
            {
                "spdxElementId": ids["cpython"],
                "relationshipType": "BUILD_TOOL_OF",
                "relatedSpdxElement": ids["Example"],
            },
        ],
    }


def test_spdx_ids_are_valid_and_tell_similar_refs_apart(describe: Describe) -> None:
    document = describe("Requires-Dist: click; os_name == 'nt'\nRequires-Dist: click; os_name != 'nt'\n")
    ids = [package["SPDXID"] for package in render_spdx(document)["packages"]]
    assert all(re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", spdx_id) for spdx_id in ids)
    assert len(set(ids)) == len(ids)


def test_repository_names_the_namespace(describe: Describe, settings: Settings) -> None:
    document = describe(settings=dataclasses.replace(settings, repository="https://github.com/example/example"))
    namespace = render_spdx(document)["documentNamespace"]
    assert namespace.startswith("https://github.com/example/example/sboms/Example-1.0-")


def test_supplier_and_application_tools_are_creators(describe: Describe, settings: Settings) -> None:
    document = describe(settings=dataclasses.replace(settings, supplier={"name": "Example Org", "url": []}))
    document["metadata"]["tools"]["components"].extend([
        {"type": "application", "bom-ref": "tool:hatchling", "name": "hatchling", "version": "1.28"},
        {"type": "application", "bom-ref": "tool:script", "name": "script"},
    ])
    assert render_spdx(document)["creationInfo"]["creators"] == [
        "Organization: Example Org",
        "Tool: hatchling-1.28",
        "Tool: script",
        f"Tool: python-sbom-{__version__}",
    ]


def test_versionless_root(describe: Describe) -> None:
    document = describe()
    del document["metadata"]["component"]["version"]
    spdx = render_spdx(document)
    assert spdx["name"] == "Example"
    assert "versionInfo" not in spdx["packages"][0]


def test_package_fields(describe: Describe) -> None:
    document = describe()
    component: Component = {
        "type": "library",
        "bom-ref": "bundled:a.whl",
        "name": "a",
        "supplier": {"name": "PyPA", "url": []},
        "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
        "externalReferences": [{"type": "website", "url": "https://example.org"}],
        "copyright": "Copyright (c) PyPA",
        "description": "a library",
        "licenses": [
            {"license": {"name": "BSD License", "acknowledgement": "declared"}},
            {"license": {"id": "MIT", "acknowledgement": "concluded"}},
        ],
        "properties": [{"name": "example:bundled-wheel", "value": "a.whl"}, {"name": "python:keywords", "value": "a"}],
        "components": [{"type": "file", "bom-ref": "bundled:a.whl#a.py", "name": "a.py"}],
    }
    document["components"].append(component)
    (package,) = (package for package in render_spdx(document)["packages"] if package["name"] == "a")
    assert {key: value for key, value in package.items() if key != "SPDXID"} == {
        "name": "a",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "NOASSERTION",
        "licenseComments": "Declared in package metadata as: BSD License",
        "primaryPackagePurpose": "LIBRARY",
        "supplier": "Organization: PyPA",
        "checksums": [{"algorithm": "SHA256", "checksumValue": "ab" * 32}],
        "homepage": "https://example.org",
        "copyrightText": "Copyright (c) PyPA",
        "summary": "a library",
        "comment": "example:bundled-wheel: a.whl",
    }


def test_license_refs_carry_extracted_text(describe: Describe) -> None:
    document = describe("License-Expression: MIT AND LicenseRef-Vendor\n")
    assert render_spdx(document).get("hasExtractedLicensingInfos") == [
        {
            "licenseId": "LicenseRef-Vendor",
            "extractedText": "LicenseRef-Vendor, as named in package metadata",
            "name": "LicenseRef-Vendor",
        }
    ]


def test_nested_libraries_are_contained(describe: Describe) -> None:
    document = describe()
    document["components"].append({
        "type": "library",
        "bom-ref": "outer",
        "name": "outer",
        "components": [{"type": "library", "bom-ref": "inner", "name": "inner"}],
    })
    spdx = render_spdx(document)
    ids = {package["name"]: package["SPDXID"] for package in spdx["packages"]}
    assert {"spdxElementId": ids["outer"], "relationshipType": "CONTAINS", "relatedSpdxElement": ids["inner"]} in spdx[
        "relationships"
    ]


@pytest.mark.parametrize(
    ("kind", "purpose"),
    [
        pytest.param("application", "APPLICATION", id="application"),
        pytest.param("library", "LIBRARY", id="library"),
        pytest.param("framework", "OTHER", id="other"),
    ],
)
def test_package_purpose(describe: Describe, kind: str, purpose: str) -> None:
    document = describe()
    document["components"].append({"type": kind, "bom-ref": "extra", "name": "extra"})
    (package,) = (package for package in render_spdx(document)["packages"] if package["name"] == "extra")
    assert package["primaryPackagePurpose"] == purpose


def test_to_spdx_text(describe: Describe) -> None:
    text = to_spdx(describe())
    assert (text.endswith("}\n"), json.loads(text)["spdxVersion"]) == (True, "SPDX-2.3")


def test_other_tools_document_renders_valid_spdx() -> None:
    assert spdx_problems(render_spdx(json.loads(_FOREIGN))) == []


def test_legacy_tools_become_creators() -> None:
    assert render_spdx(json.loads(_FOREIGN))["creationInfo"]["creators"] == [
        "Tool: auditwheel-6.4.0",
        "Tool: repair",
        f"Tool: python-sbom-{__version__}",
    ]


def test_document_without_tools() -> None:
    foreign = json.loads(_FOREIGN)
    del foreign["metadata"]["tools"]
    assert render_spdx(foreign)["creationInfo"]["creators"] == [f"Tool: python-sbom-{__version__}"]


def test_namespace_without_serial_names_the_content() -> None:
    changed = json.loads(_FOREIGN)
    changed["version"] = 2
    namespaces = [render_spdx(document)["documentNamespace"] for document in (json.loads(_FOREIGN),) * 2]
    assert (namespaces[0] == namespaces[1], namespaces[0] == render_spdx(changed)["documentNamespace"]) == (
        True,
        False,
    )


def test_creation_time_without_timestamp_is_the_rendering_time() -> None:
    before = datetime.now(UTC).replace(microsecond=0)
    created = datetime.fromisoformat(render_spdx(json.loads(_FOREIGN))["creationInfo"]["created"])
    assert before <= created <= datetime.now(UTC)


def test_supplier_without_name_is_no_creator(describe: Describe) -> None:
    # the schema makes the name optional, so the loaded JSON, not the typed document, loses it
    loaded = json.loads(dumps(describe()))
    loaded["metadata"]["supplier"] = {"url": ["https://example.org"]}
    assert render_spdx(loaded)["creationInfo"]["creators"] == [f"Tool: python-sbom-{__version__}"]


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        pytest.param("SHA-1", "SHA1", id="sha1"),
        pytest.param("SHA-512", "SHA512", id="sha512"),
        pytest.param("SHA3-256", "SHA3-256", id="sha3"),
        pytest.param("BLAKE2b-256", "BLAKE2b-256", id="blake2b"),
        pytest.param("BLAKE3", "BLAKE3", id="blake3"),
    ],
)
def test_hash_algorithms_take_spdx_names(algorithm: str, expected: str) -> None:
    (package,) = packages_of({"hashes": [{"alg": algorithm, "content": "ab" * 32}]})
    assert package.get("checksums") == [{"algorithm": expected, "checksumValue": "ab" * 32}]


def packages_of(fields: dict[str, _Json]) -> list[_Package]:
    document = json.loads(_FOREIGN)
    document["components"] = [{"type": "library", "bom-ref": "lib", "name": "lib", **fields}]
    return [package for package in render_spdx(document)["packages"] if package["name"] == "lib"]


def test_hash_algorithm_spdx_lacks_is_dropped() -> None:
    (package,) = packages_of({"hashes": [{"alg": "SHA-224", "content": "ab" * 28}]})
    assert "checksums" not in package


def test_component_supplier_without_name_is_dropped() -> None:
    (package,) = packages_of({"supplier": {"url": ["https://example.org"]}})
    assert "supplier" not in package


def test_property_without_value() -> None:
    (package,) = packages_of({"properties": [{"name": "plain:extra"}]})
    assert package["comment"] == "plain:extra: "
