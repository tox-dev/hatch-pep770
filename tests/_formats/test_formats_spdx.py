from __future__ import annotations

import dataclasses
import re
from typing import TYPE_CHECKING

import pytest

from python_sbom import to_spdx

if TYPE_CHECKING:
    from conftest import Describe

    from python_sbom import Component, Settings


def test_minimal(describe: Describe) -> None:
    document = describe()
    spdx = to_spdx(document, "1.2.3")
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
        "creationInfo": {"created": "2023-11-14T22:13:20Z", "creators": ["Tool: python-sbom-1.2.3"]},
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
    ids = [package["SPDXID"] for package in to_spdx(document, "1")["packages"]]
    assert all(re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", spdx_id) for spdx_id in ids)
    assert len(set(ids)) == len(ids)


def test_repository_names_the_namespace(describe: Describe, settings: Settings) -> None:
    document = describe(settings=dataclasses.replace(settings, repository="https://github.com/example/example"))
    namespace = to_spdx(document, "1")["documentNamespace"]
    assert namespace.startswith("https://github.com/example/example/sboms/Example-1.0-")


def test_supplier_and_application_tools_are_creators(describe: Describe, settings: Settings) -> None:
    document = describe(settings=dataclasses.replace(settings, supplier={"name": "Example Org", "url": []}))
    document["metadata"]["tools"]["components"].extend([
        {"type": "application", "bom-ref": "tool:hatchling", "name": "hatchling", "version": "1.28"},
        {"type": "application", "bom-ref": "tool:script", "name": "script"},
    ])
    assert to_spdx(document, "1")["creationInfo"]["creators"] == [
        "Organization: Example Org",
        "Tool: hatchling-1.28",
        "Tool: script",
        "Tool: python-sbom-1",
    ]


def test_versionless_root(describe: Describe) -> None:
    document = describe()
    del document["metadata"]["component"]["version"]
    spdx = to_spdx(document, "1")
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
    (package,) = (package for package in to_spdx(document, "1")["packages"] if package["name"] == "a")
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
    assert to_spdx(document, "1").get("hasExtractedLicensingInfos") == [
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
    spdx = to_spdx(document, "1")
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
    (package,) = (package for package in to_spdx(document, "1")["packages"] if package["name"] == "extra")
    assert package["primaryPackagePurpose"] == purpose
