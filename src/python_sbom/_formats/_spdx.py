from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NotRequired, TypedDict

from python_sbom.version import version

if TYPE_CHECKING:
    from collections.abc import Iterator

    from python_sbom._model._types import Component, Document, License


class _Checksum(TypedDict):
    algorithm: str
    checksumValue: str


class _ExternalRef(TypedDict):
    referenceCategory: str
    referenceType: str
    referenceLocator: str


class _Package(TypedDict):
    SPDXID: str
    name: str
    downloadLocation: str
    filesAnalyzed: bool
    licenseConcluded: str
    licenseDeclared: str
    primaryPackagePurpose: str
    versionInfo: NotRequired[str]
    supplier: NotRequired[str]
    checksums: NotRequired[list[_Checksum]]
    homepage: NotRequired[str]
    copyrightText: NotRequired[str]
    summary: NotRequired[str]
    comment: NotRequired[str]
    externalRefs: NotRequired[list[_ExternalRef]]
    licenseComments: NotRequired[str]


class _Relationship(TypedDict):
    spdxElementId: str
    relationshipType: str
    relatedSpdxElement: str


class _CreationInfo(TypedDict):
    created: str
    creators: list[str]


class Spdx(TypedDict):
    """An SPDX 2.3 JSON document."""

    spdxVersion: str
    dataLicense: str
    SPDXID: str
    name: str
    documentNamespace: str
    comment: str
    creationInfo: _CreationInfo
    packages: list[_Package]
    relationships: list[_Relationship]


def to_spdx(bom: Document) -> Spdx:
    """
    Render a CycloneDX document as SPDX 2.3.

    Packages keep their hashes, licenses and purls, and the containment, dependency and build tool relationships carry
    over. Per-file hashes stay behind, because SPDX 2.3 requires a SHA-1 for every file and wheel ``RECORD`` files hold
    SHA-256, and so does the build formulation, which SPDX 2.3 has no field for.

    :param bom: a CycloneDX document as this package writes it
    :returns: the SPDX document, whose namespace ends in the CycloneDX serial number so both name the same build

    """
    root: Final[Component] = bom["metadata"]["component"]
    tools: Final[list[Component]] = bom["metadata"]["tools"]["components"]
    name: Final[str] = f"{root['name']}-{root['version']}" if "version" in root else root["name"]
    namespace: Final[str] = re.sub(r"[-_.]+", "-", root["name"]).lower()
    repository: Final[str] = next(
        (
            reference["url"]
            for reference in root.get("externalReferences", [])
            if reference["type"] == "vcs" and "Project-URL" in reference.get("comment", "")
        ),
        "https://spdx.org/spdxdocs",
    )
    components: Final[list[Component]] = list(_walk([root, *bom["components"], *tools]))
    supplier: Final[list[str]] = (
        [f"Organization: {bom['metadata']['supplier']['name']}"] if "supplier" in bom["metadata"] else []
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"{repository}/sboms/{name}-{bom['serialNumber'].removeprefix('urn:uuid:')}",
        "comment": f"Rendered from the CycloneDX SBOM {bom['serialNumber']} ({namespace}.cdx.json), which also carries"
        " per-file hashes and the build formulation.",
        "creationInfo": {
            "created": datetime
            .fromisoformat(bom["metadata"]["timestamp"])
            .astimezone(UTC)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [
                *supplier,
                *(f"Tool: {tool['name']}-{tool['version']}" for tool in tools if tool["type"] == "application"),
                f"Tool: python-sbom-{version}",
            ],
        },
        "packages": [_package(component, f"{namespace}:") for component in components],
        "relationships": [
            _relationship("SPDXRef-DOCUMENT", "DESCRIBES", _spdx_id(root["bom-ref"])),
            *(
                _relationship(_spdx_id(parent["bom-ref"]), "CONTAINS", _spdx_id(child["bom-ref"]))
                for parent in components
                for child in parent.get("components", [])
                if child["type"] != "file"
            ),
            *(
                _relationship(_spdx_id(entry["ref"]), "DEPENDS_ON", _spdx_id(dependency))
                for entry in bom["dependencies"]
                for dependency in entry.get("dependsOn", [])
            ),
            *(_relationship(_spdx_id(tool["bom-ref"]), "BUILD_TOOL_OF", _spdx_id(root["bom-ref"])) for tool in tools),
        ],
    }


def _walk(components: list[Component]) -> Iterator[Component]:
    # file components mirror wheel RECORD entries, which carry no SHA-1 and so cannot become SPDX files
    for component in components:
        if component["type"] != "file":
            yield component
            yield from _walk(component.get("components", []))


def _package(component: Component, property_prefix: str) -> _Package:
    # the hook writes either one SPDX expression, or the free-form names from License/classifier metadata plus the SPDX
    # ids it concluded from them
    licenses: Final[list[License]] = component.get("licenses", [])
    concluded: Final[list[str]] = [
        entry["license"]["id"] for entry in licenses if "license" in entry and "id" in entry["license"]
    ]
    package: Final[_Package] = {
        "SPDXID": _spdx_id(component["bom-ref"]),
        "name": component["name"],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": " AND ".join(concluded) or "NOASSERTION",
        "licenseDeclared": next((entry["expression"] for entry in licenses if "expression" in entry), "NOASSERTION"),
        "primaryPackagePurpose": {"application": "APPLICATION", "library": "LIBRARY", "platform": "OTHER"}[
            component["type"]
        ],
    }
    if version := component.get("version"):
        package["versionInfo"] = version
    if supplier := component.get("supplier"):
        package["supplier"] = f"Organization: {supplier['name']}"
    if hashes := component.get("hashes"):
        package["checksums"] = [
            {"algorithm": entry["alg"].replace("-", ""), "checksumValue": entry["content"]} for entry in hashes
        ]
    references = component.get("externalReferences", [])
    if homepage := next((reference["url"] for reference in references if reference["type"] == "website"), None):
        package["homepage"] = homepage
    if copyright_text := component.get("copyright"):
        package["copyrightText"] = copyright_text
    if description := component.get("description"):
        package["summary"] = description
    if comment := "\n".join(
        f"{prop['name']}: {prop['value']}"
        for prop in component.get("properties", [])
        if prop["name"].startswith(property_prefix)
    ):
        package["comment"] = comment
    if purl := component.get("purl"):
        package["externalRefs"] = [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}
        ]
    if package["licenseDeclared"] == "NOASSERTION" and (
        names := [entry["license"]["name"] for entry in licenses if "license" in entry and "name" in entry["license"]]
    ):
        package["licenseComments"] = f"Declared in package metadata as: {'; '.join(names)}"
    return package


def _relationship(element: str, kind: str, related: str) -> _Relationship:
    return {"spdxElementId": element, "relationshipType": kind, "relatedSpdxElement": related}


def _spdx_id(bom_ref: str) -> str:
    # SPDX ids allow letters, digits, "." and "-"; the digest keeps two refs that differ only in other characters,
    # such as the markers of two conditional requirements, apart
    readable = re.sub(r"[^A-Za-z0-9.]+", "-", bom_ref).strip("-")
    return f"SPDXRef-{readable}-{hashlib.sha256(bom_ref.encode()).hexdigest()[:8]}"


__all__ = [
    "Spdx",
    "to_spdx",
]
