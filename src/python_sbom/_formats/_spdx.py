from __future__ import annotations

from typing import TYPE_CHECKING, NotRequired, TypedDict

from python_sbom import _core
from python_sbom.version import __version__

if TYPE_CHECKING:
    from python_sbom._model._types import Document


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


def to_spdx(document: Document) -> str:
    return _core.spdx_text(document, __version__)


def render_spdx(bom: Document, tool_version: str) -> Spdx:
    return _core.render_spdx(bom, tool_version)


__all__ = [
    "Spdx",
    "render_spdx",
    "to_spdx",
]
