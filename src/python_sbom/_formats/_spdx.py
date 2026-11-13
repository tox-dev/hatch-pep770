"""Render a CycloneDX document as an SPDX 2.3 document."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NotRequired, TypedDict

from python_sbom._model._graph import walk_components  # simplint: ignore[private-import-path]  # avoid root export
from python_sbom._model._names import (  # simplint: ignore[private-import-path]  # avoid root export
    SBOM_FILE,
    SBOM_REPOSITORY,
    property_prefix,
    sbom_property,
)
from python_sbom.version import __version__

if TYPE_CHECKING:
    from python_sbom._model._types import (  # simplint: ignore[private-import-path]  # avoid root export
        Component,
        Document,
        ExternalReference,
        License,
        Metadata,
        OrganizationalEntity,
        Tools,
    )

# SPDX 2.3 JSON names every CycloneDX 1.6 hash algorithm, but by names of its own
_HASH_ALGORITHMS: Final[dict[str, str]] = {
    "MD5": "MD5",
    "SHA-1": "SHA1",
    "SHA-256": "SHA256",
    "SHA-384": "SHA384",
    "SHA-512": "SHA512",
    "SHA3-256": "SHA3-256",
    "SHA3-384": "SHA3-384",
    "SHA3-512": "SHA3-512",
    "BLAKE2b-256": "BLAKE2b-256",
    "BLAKE2b-384": "BLAKE2b-384",
    "BLAKE2b-512": "BLAKE2b-512",
    "BLAKE3": "BLAKE3",
}
_LICENSE_REF: Final[re.Pattern[str]] = re.compile(r"LicenseRef-[A-Za-z0-9.-]+")
_SPDX_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9.]+")


class _LegacyTool(TypedDict):
    vendor: NotRequired[str]
    name: NotRequired[str]
    version: NotRequired[str]


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


def render_spdx(document: Document) -> Spdx:
    metadata: Final[Metadata] = document["metadata"]
    root: Final[Component] = metadata["component"]
    project: Final[str] = property_prefix(root["name"])
    recorded: Final[dict[str, str]] = {prop["name"]: prop.get("value", "") for prop in metadata.get("properties", [])}
    name: Final[str] = f"{root['name']}-{root['version']}" if "version" in root else root["name"]
    # without a serial number the content names the document, so rendering it twice gives the same namespace
    source: Final[str] = (
        document["serialNumber"]
        if "serialNumber" in document
        else f"sha256:{hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()}"
    )
    repository: Final[str] = recorded.get(sbom_property(project, SBOM_REPOSITORY), "https://spdx.org/spdxdocs")
    sbom_file: Final[str] = recorded.get(sbom_property(project, SBOM_FILE), "CycloneDX JSON")
    tools, tool_creators = _tools(metadata)
    # file components mirror wheel RECORD entries, which carry no SHA-1 and so cannot become SPDX files
    components: Final[list[Component]] = [
        component
        for component in walk_components([root, *document.get("components", []), *tools])
        if component["type"] != "file"
    ]
    packages: Final[list[_Package]] = [_package(component, project) for component in components]
    spdx: Final[Spdx] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"{repository}/sboms/{name}-{source.removeprefix('urn:uuid:')}",
        "comment": f"Rendered from the CycloneDX SBOM {source} ({sbom_file}), which also carries per-file hashes and"
        " the build formulation.",
        "creationInfo": _creation_info(metadata, tool_creators),
        "packages": packages,
        "relationships": _relationships(document, components, tools),
    }
    # SPDX requires the text of every LicenseRef a package declares; the metadata names them, it holds no text
    references: Final[set[str]] = set()
    for package in packages:
        references.update(_LICENSE_REF.findall(package["licenseDeclared"]))
    if references:
        spdx["hasExtractedLicensingInfos"] = [
            {"licenseId": token, "extractedText": f"{token}, as named in package metadata", "name": token}
            for token in sorted(references)
        ]
    return spdx


def _tools(metadata: Metadata) -> tuple[list[Component], list[str]]:
    # CycloneDX 1.5 lists the tools as components; earlier versions as a bare array, whose entries carry no bom-ref, so
    # they become creators alone
    tools: Final[Tools | list[_LegacyTool] | None] = metadata.get("tools")
    if isinstance(tools, list):
        return [], [_creator(name, tool.get("version")) for tool in tools if (name := tool.get("name"))]
    components: Final[list[Component]] = [] if tools is None else tools.get("components", [])
    return components, [
        _creator(tool["name"], tool.get("version")) for tool in components if tool["type"] == "application"
    ]


def _creator(name: str, version: str | None) -> str:
    return f"Tool: {name}" if version is None else f"Tool: {name}-{version}"


def _package(component: Component, project: str) -> _Package:
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
    if (supplier := component.get("supplier")) and (organization := supplier.get("name")):
        package["supplier"] = f"Organization: {organization}"
    checksums: Final[list[_Checksum]] = [
        {"algorithm": _HASH_ALGORITHMS[entry["alg"]], "checksumValue": entry["content"]}
        for entry in component.get("hashes", [])
        if entry["alg"] in _HASH_ALGORITHMS
    ]
    if checksums:
        package["checksums"] = checksums
    references: Final[list[ExternalReference]] = component.get("externalReferences", [])
    if homepage := next((reference["url"] for reference in references if reference["type"] == "website"), None):
        package["homepage"] = homepage
    if copyright_text := component.get("copyright"):
        package["copyrightText"] = copyright_text
    if description := component.get("description"):
        package["summary"] = description
    if comment := "\n".join(
        f"{prop['name']}: {prop.get('value', '')}"
        for prop in component.get("properties", [])
        if prop["name"].startswith(f"{project}:")
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


def _spdx_id(bom_ref: str) -> str:
    # the readable part drops every other character, so refs that differ only in those share it; only the full digest,
    # not a prefix of it, keeps their ids apart
    readable: Final[str] = _SPDX_ID_PATTERN.sub("-", bom_ref).strip("-")
    return f"SPDXRef-{readable}-{hashlib.sha256(bom_ref.encode()).hexdigest()}"


def _creation_info(metadata: Metadata, tool_creators: list[str]) -> _CreationInfo:
    timestamp: Final[str | None] = metadata.get("timestamp")
    # SPDX requires a creation time; without the CycloneDX one, the time of this rendering is the true one
    created: Final[datetime] = datetime.now(UTC) if timestamp is None else datetime.fromisoformat(timestamp)
    supplier: Final[OrganizationalEntity | None] = metadata.get("supplier")
    organization: Final[str] = "" if supplier is None else supplier.get("name", "")
    creators: Final[list[str]] = [f"Organization: {organization}"] if organization else []
    creators.extend(tool_creators)
    creators.append(f"Tool: python-sbom-{__version__}")
    return {"created": created.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": creators}


def _relationships(document: Document, components: list[Component], tools: list[Component]) -> list[_Relationship]:
    root_id: Final[str] = _spdx_id(document["metadata"]["component"]["bom-ref"])
    relationships: Final[list[_Relationship]] = [_relationship("SPDXRef-DOCUMENT", "DESCRIBES", root_id)]
    for parent in components:
        parent_id = _spdx_id(parent["bom-ref"])
        children = (child for child in parent.get("components", []) if child["type"] != "file")
        relationships.extend(_relationship(parent_id, "CONTAINS", _spdx_id(child["bom-ref"])) for child in children)
    for entry in document.get("dependencies", []):
        dependent_id = _spdx_id(entry["ref"])
        relationships.extend(
            _relationship(dependent_id, "DEPENDS_ON", _spdx_id(dependency)) for dependency in entry.get("dependsOn", [])
        )
    relationships.extend(_relationship(_spdx_id(tool["bom-ref"]), "BUILD_TOOL_OF", root_id) for tool in tools)
    return relationships


def _relationship(element: str, kind: str, related: str) -> _Relationship:
    return {"spdxElementId": element, "relationshipType": kind, "relatedSpdxElement": related}


__all__ = [
    "Spdx",
    "render_spdx",
]
