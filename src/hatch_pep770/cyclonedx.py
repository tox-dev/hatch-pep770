"""CycloneDX 1.6 building blocks shared by the build hook and by projects that describe other artifacts."""

from __future__ import annotations

import base64
import json
import platform
import re
import sys
import uuid
from datetime import datetime, timezone
from email.parser import Parser
from email.utils import getaddresses
from importlib.metadata import distributions
from typing import TYPE_CHECKING, Final, TypedDict

from hatchling.builders.utils import get_reproducible_timestamp
from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.requirements import Requirement

if TYPE_CHECKING:
    from email.message import Message
    from importlib.metadata import Distribution, PackageMetadata


class OrganizationalEntity(TypedDict):
    name: str
    url: list[str]


class Contact(TypedDict, total=False):
    name: str
    email: str


class Hash(TypedDict):
    alg: str
    content: str


class Property(TypedDict):
    name: str
    value: str


class _ExternalReferenceKeys(TypedDict):
    type: str
    url: str


class ExternalReference(_ExternalReferenceKeys, total=False):
    comment: str


class _LicenseIdentity(TypedDict, total=False):
    id: str
    name: str


class LicenseInfo(_LicenseIdentity):
    acknowledgement: str


class License(TypedDict, total=False):
    # a CycloneDX license choice holds either a `license` or an `expression` with its `acknowledgement`
    license: LicenseInfo
    expression: str
    acknowledgement: str


class _Method(TypedDict):
    technique: str
    confidence: int
    value: str


class _Identity(TypedDict):
    field: str
    confidence: int
    methods: list[_Method]


class Evidence(TypedDict):
    identity: list[_Identity]


_ComponentKeys = TypedDict("_ComponentKeys", {"type": str, "bom-ref": str, "name": str})


class _ComponentFields(TypedDict, total=False):
    version: str
    purl: str
    supplier: OrganizationalEntity
    authors: list[Contact]
    description: str
    licenses: list[License]
    copyright: str
    hashes: list[Hash]
    externalReferences: list[ExternalReference]
    properties: list[Property]
    evidence: Evidence
    components: list[Component]


class Component(_ComponentKeys, _ComponentFields):
    pass


class Dependency(TypedDict):
    ref: str
    dependsOn: list[str]


class _Ref(TypedDict):
    ref: str


class _Output(TypedDict):
    type: str
    resource: _Ref


class _Input(TypedDict):
    environmentVars: list[Property]


Workflow = TypedDict(
    "Workflow",
    {
        "bom-ref": str,
        "uid": str,
        "name": str,
        "taskTypes": list[str],
        "resourceReferences": list[_Ref],
        "inputs": list[_Input],
        "outputs": list[_Output],
    },
)
Formula = TypedDict("Formula", {"bom-ref": str, "workflows": list[Workflow]})


class _Lifecycle(TypedDict):
    phase: str


class _Tools(TypedDict):
    components: list[Component]


class _MetadataKeys(TypedDict):
    timestamp: str
    lifecycles: list[_Lifecycle]
    tools: _Tools
    component: Component


class Metadata(_MetadataKeys, total=False):
    manufacturer: OrganizationalEntity
    supplier: OrganizationalEntity
    authors: list[Contact]
    licenses: list[License]
    properties: list[Property]


class Composition(TypedDict):
    aggregate: str
    dependencies: list[str]


class _BodyKeys(TypedDict):
    metadata: Metadata
    components: list[Component]
    dependencies: list[Dependency]
    formulation: list[Formula]


class Body(_BodyKeys, total=False):
    compositions: list[Composition]


_Header = TypedDict(
    "_Header", {"$schema": str, "bomFormat": str, "specVersion": str, "serialNumber": str, "version": int}
)


class Document(_Header, Body):
    pass


# the label normalization and mapping cyclonedx-py applies to Project-URL entries, plus "source", so the same metadata
# yields the same reference types whichever generator produced the document
_URL_LABEL_TO_REFERENCE_TYPE: Final[dict[str, str]] = {
    "bugtracker": "issue-tracker",
    "issuetracker": "issue-tracker",
    "issues": "issue-tracker",
    "bugreports": "issue-tracker",
    "tracker": "issue-tracker",
    "home": "website",
    "homepage": "website",
    "download": "distribution",
    "documentation": "documentation",
    "docs": "documentation",
    "changelog": "release-notes",
    "changes": "release-notes",
    "source": "vcs",
    "repository": "vcs",
    "github": "vcs",
    "chat": "chat",
}
# core metadata headers copied verbatim onto a component as properties
_METADATA_PROPERTIES: Final[tuple[str, ...]] = (
    "Requires-Python",
    "Requires-Dist",
    "Provides-Extra",
    "Classifier",
    "Keywords",
)
# only the license classifiers that name exactly one SPDX license; "BSD License" or "Apache Software License" leave the
# version or variant open
_CLASSIFIER_LICENSES: Final[dict[str, str]] = {
    "ISC License (ISCL)": "ISC",
    "MIT License": "MIT",
    "MIT No Attribution License (MIT-0)": "MIT-0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
}
_RECORD_HASH_ALGORITHMS: Final[dict[str, str]] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


def document(body: Body, namespace: uuid.UUID) -> Document:
    """
    Wrap a document body in the CycloneDX 1.6 header.

    :param body: the metadata, components, dependencies and formulation of the document
    :param namespace: UUID namespace for the serial number, one per project
    :returns: the complete document, whose serial number derives from the body so identical bodies share it

    """
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }


def timestamp() -> str:
    """
    Format the build time for the document.

    :returns: the ISO 8601 time from ``SOURCE_DATE_EPOCH``, or hatchling's fixed default when unset

    """
    return datetime.fromtimestamp(get_reproducible_timestamp(), tz=timezone.utc).isoformat()


def purl(name: str, version: str | None = None) -> str:
    """
    Build the package URL of a Python distribution.

    :param name: distribution name, normalized here
    :param version: version, or ``None`` for an unversioned purl
    :returns: the ``pkg:pypi`` package URL

    """
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:pypi/{normalized}@{version}" if version else f"pkg:pypi/{normalized}"


def external_reference(label: str, url: str) -> ExternalReference:
    """
    Turn a ``Project-URL`` entry into an external reference.

    :param label: the entry's label, which picks the reference type
    :param url: the entry's URL
    :returns: the reference, typed ``other`` when the label is not a known one

    """
    reference_type = _URL_LABEL_TO_REFERENCE_TYPE.get(re.sub(r"[^a-z]", "", label.lower()), "other")
    return {"type": reference_type, "url": url, "comment": f"Project-URL: {label}"}


def contacts(names: list[str], addresses: list[str]) -> list[Contact]:
    """
    Turn core metadata author or maintainer fields into CycloneDX contacts.

    :param names: bare names, from ``Author`` or ``Maintainer``
    :param addresses: RFC 5322 addresses, from ``Author-email`` or ``Maintainer-email``
    :returns: one contact per name, then one per address

    """
    found: list[Contact] = [{"name": name} for name in names]
    for name, email in getaddresses(addresses):
        contact: Contact = {}
        if name:
            contact["name"] = name
        if email:
            contact["email"] = email
        found.append(contact)
    return found


def component_from_metadata(metadata: PackageMetadata | Message, component_type: str) -> Component:
    """
    Describe a distribution from its core metadata.

    :param metadata: the distribution's ``METADATA``
    :param component_type: the CycloneDX component type, such as ``library``
    :returns: the component, with its purl as ``bom-ref``, licenses, Project-URL references and metadata properties

    """
    name, version = metadata["Name"], metadata["Version"]
    component: Final[Component] = {
        "type": component_type,
        "bom-ref": (package := purl(name, version)),
        "name": name,
        "version": version,
        "purl": package,
    }
    if summary := metadata.get("Summary"):
        component["description"] = summary
    if authors := contacts(
        metadata.get_all("Author", []) + metadata.get_all("Maintainer", []),
        metadata.get_all("Author-email", []) + metadata.get_all("Maintainer-email", []),
    ):
        component["authors"] = authors
    if licenses := _licenses(metadata):
        component["licenses"] = licenses
    component["externalReferences"] = [
        external_reference(label.strip(), url.strip())
        for label, url in (entry.split(",", 1) for entry in metadata.get_all("Project-URL", []))
    ]
    if home_page := metadata.get("Home-page"):
        component["externalReferences"].insert(0, {"type": "website", "url": home_page})
    component["properties"] = [
        {"name": f"python:{header.lower()}", "value": value}
        for header in _METADATA_PROPERTIES
        for value in metadata.get_all(header, [])
    ]
    return component


def _licenses(metadata: PackageMetadata | Message) -> list[License]:
    if expression := metadata.get("License-Expression"):
        return [{"expression": expression, "acknowledgement": "declared"}]
    names = [
        entry.rsplit(" :: ", 1)[-1] for entry in metadata.get_all("Classifier", []) if entry.startswith("License :: ")
    ]
    if (declared := metadata.get("License")) and "\n" not in declared:
        names.append(declared)
    licenses: Final[list[License]] = [{"license": {"name": name, "acknowledgement": "declared"}} for name in names]
    # a license policy judges SPDX ids only, so a component keeps its bare names when any one of them does not resolve,
    # and the policy reports it instead of judging a partial set
    identifiers: Final[list[str]] = [identifier for name in names if (identifier := _spdx_license(name)) is not None]
    if len(identifiers) == len(names):
        licenses.extend(
            {"license": {"id": identifier, "acknowledgement": "concluded"}} for identifier in dict.fromkeys(identifiers)
        )
    return licenses


def _spdx_license(name: str) -> str | None:
    if identifier := _CLASSIFIER_LICENSES.get(name):
        return identifier
    try:
        canonical = canonicalize_license_expression(name)
    except InvalidLicenseExpression:
        return None
    # a CycloneDX license id holds one entry of the SPDX license list, never an expression or a LicenseRef
    return canonical if re.fullmatch(r"[A-Za-z0-9.-]+", canonical) and not canonical.startswith("LicenseRef-") else None


def file_component(parent_ref: str, path: str, digest: str, size: str) -> Component:
    """
    Describe one file from a wheel ``RECORD`` row.

    :param parent_ref: ``bom-ref`` of the component that holds the file
    :param path: the file's path inside the wheel
    :param digest: the ``RECORD`` digest, ``<algorithm>=<urlsafe base64 without padding>``
    :param size: the file's size in bytes
    :returns: a ``file`` component with the digest as a lowercase hex hash

    """
    algorithm, _, encoded = digest.partition("=")
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    return {
        "type": "file",
        "bom-ref": f"{parent_ref}#{path}",
        "name": path,
        "hashes": [{"alg": _RECORD_HASH_ALGORITHMS[algorithm], "content": raw.hex()}],
        "properties": [{"name": "size", "value": size}],
    }


def build_tools() -> tuple[list[Component], list[Dependency]]:
    """
    Describe the running build environment: the interpreter and every installed distribution.

    Nothing about the build machine goes in, so the same toolchain yields the same record on any operating system or
    architecture. A pure-Python distribution lists its files with their hashes; a platform one does not, because its
    files differ per machine.

    :returns: the tool components, interpreter first, and the dependency graph between the distributions

    """
    interpreter = f"pkg:generic/{sys.implementation.name}@{platform.python_version()}"
    tools: Final[list[Component]] = [
        {
            "type": "platform",
            "bom-ref": f"tool:{interpreter}",
            "name": sys.implementation.name,
            "version": platform.python_version(),
            "purl": interpreter,
            "properties": [{"name": "python:implementation", "value": platform.python_implementation()}],
        },
    ]
    # bom-refs are prefixed because the same distribution can be both a build tool and a component of the artifact
    installed = {purl(distribution.metadata["Name"]): distribution for distribution in distributions()}
    tool_dependencies: Final[list[Dependency]] = []
    for distribution in (installed[key] for key in sorted(installed)):
        component = component_from_metadata(distribution.metadata, "library")
        component["bom-ref"] = f"tool:{component['purl']}"
        if Parser().parsestr(distribution.read_text("WHEEL") or "")["Root-Is-Purelib"] == "true":
            component["components"] = [
                file_component(
                    component["bom-ref"], file.as_posix(), f"{file.hash.mode}={file.hash.value}", str(file.size)
                )
                for file in distribution.files or []
                # console-script launchers live outside site-packages and embed the build env's interpreter path in
                # their shebang, so their hash differs on every build and says nothing about the distribution; the
                # installer metadata names the build frontend that set up the env rather than the distribution
                if file.hash is not None
                and not file.as_posix().startswith("../")
                and not (
                    file.parent.suffix == ".dist-info" and file.name in {"INSTALLER", "REQUESTED", "direct_url.json"}
                )
            ]
        tools.append(component)
        tool_dependencies.append({"ref": component["bom-ref"], "dependsOn": _depends_on(distribution, installed)})
    return tools, tool_dependencies


def _depends_on(distribution: Distribution, installed: dict[str, Distribution]) -> list[str]:
    refs = set()
    for requirement in map(Requirement, distribution.requires or []):
        if (requirement.marker is None or requirement.marker.evaluate()) and (
            dependency := installed.get(purl(requirement.name))
        ):
            refs.add(f"tool:{purl(dependency.metadata['Name'], dependency.version)}")
    return sorted(refs)


__all__ = [
    "Body",
    "Component",
    "Composition",
    "Contact",
    "Dependency",
    "Document",
    "Evidence",
    "ExternalReference",
    "Formula",
    "Hash",
    "License",
    "LicenseInfo",
    "Metadata",
    "OrganizationalEntity",
    "Property",
    "Workflow",
    "build_tools",
    "component_from_metadata",
    "contacts",
    "document",
    "external_reference",
    "file_component",
    "purl",
    "timestamp",
]
