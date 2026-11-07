from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NotRequired, TypedDict

from packaging.utils import canonicalize_name

if TYPE_CHECKING:
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


class _ExtractedLicense(TypedDict):
    licenseId: str
    extractedText: str
    name: str


class Spdx(TypedDict):
    """
    An SPDX 2.3 JSON document, as :func:`to_spdx` renders it.

    :ivar spdxVersion: ``SPDX-2.3``
    :ivar dataLicense: ``CC0-1.0``
    :ivar SPDXID: ``SPDXRef-DOCUMENT``
    :ivar name: the root component's name and version
    :ivar documentNamespace: a URI that ends in the CycloneDX serial number
    :ivar comment: which CycloneDX document it was rendered from
    :ivar creationInfo: the build time and the creators
    :ivar packages: one package per component, files aside
    :ivar relationships: containment, dependency and build tool relationships
    :ivar hasExtractedLicensingInfos: one entry per ``LicenseRef-`` a package declares

    """

    spdxVersion: str
    dataLicense: str
    SPDXID: str
    name: str
    documentNamespace: str
    comment: str
    creationInfo: _CreationInfo
    packages: list[_Package]
    relationships: list[_Relationship]
    hasExtractedLicensingInfos: NotRequired[list[_ExtractedLicense]]


def to_spdx(bom: Document, tool_version: str) -> Spdx:
    """
    Render a CycloneDX document as SPDX 2.3.

    Packages keep their hashes, licenses and purls, and the containment, dependency and build tool relationships carry
    over. Per-file hashes stay behind, because SPDX 2.3 requires a SHA-1 for every file and wheel ``RECORD`` files hold
    SHA-256, and so does the build formulation, which SPDX 2.3 has no field for.

    :param bom: a CycloneDX document; python-sbom's own documents name their file and repository, others fall back
    :param tool_version: the python-sbom version to name as a creator
    :returns: the SPDX document, whose namespace ends in the CycloneDX serial number so both name the same build

    """
    root: Final[Component] = bom["metadata"]["component"]
    tools: Final[list[Component]] = bom["metadata"]["tools"]["components"]
    prefix = f"{canonicalize_name(root['name'])}:"
    recorded = {prop["name"]: prop["value"] for prop in bom["metadata"].get("properties", [])}
    name: Final[str] = f"{root['name']}-{root['version']}" if "version" in root else root["name"]
    serial = bom["serialNumber"].removeprefix("urn:uuid:")
    components: Final[list[Component]] = _walk([root, *bom["components"], *tools])
    packages = [_package(component, prefix) for component in components]
    spdx: Final[Spdx] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"{recorded.get(f'{prefix}sbom:repository', 'https://spdx.org/spdxdocs')}/sboms/{name}-{serial}",
        "comment": f"Rendered from the CycloneDX SBOM {bom['serialNumber']}"
        f" ({recorded.get(f'{prefix}sbom:file', 'CycloneDX JSON')}), which also carries per-file hashes and the build"
        " formulation.",
        "creationInfo": {
            "created": datetime
            .fromisoformat(bom["metadata"]["timestamp"])
            .astimezone(UTC)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [
                *(
                    [f"Organization: {supplier['name']}"]
                    if (supplier := bom["metadata"].get("supplier")) is not None
                    else []
                ),
                *(
                    f"Tool: {tool['name']}-{tool['version']}" if "version" in tool else f"Tool: {tool['name']}"
                    for tool in tools
                    if tool["type"] == "application"
                ),
                f"Tool: python-sbom-{tool_version}",
            ],
        },
        "packages": packages,
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
    # SPDX requires the text of every LicenseRef a package declares; the metadata names them, it holds no text
    if references := sorted({
        token for package in packages for token in re.findall(r"LicenseRef-[A-Za-z0-9.-]+", package["licenseDeclared"])
    }):
        spdx["hasExtractedLicensingInfos"] = [
            {"licenseId": token, "extractedText": f"{token}, as named in package metadata", "name": token}
            for token in references
        ]
    return spdx


def _walk(components: list[Component]) -> list[Component]:
    # iterative, so a deeply nested hostile document cannot exhaust the stack; file components mirror wheel RECORD
    # entries, which carry no SHA-1 and so cannot become SPDX files
    found: Final[list[Component]] = []
    pending = list(reversed(components))
    while pending:
        if (component := pending.pop())["type"] != "file":
            found.append(component)
            pending.extend(reversed(component.get("components", [])))
    return found


def _package(component: Component, property_prefix: str) -> _Package:
    # a component carries either one SPDX expression, or the free-form names from License/classifier metadata plus the
    # SPDX ids concluded from them
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
        "primaryPackagePurpose": {"application": "APPLICATION", "library": "LIBRARY"}.get(component["type"], "OTHER"),
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
