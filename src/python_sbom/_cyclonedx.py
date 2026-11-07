from __future__ import annotations

import base64
import hashlib
import json
import platform
import re
import sys
import uuid
from datetime import UTC, datetime
from email.parser import Parser
from email.utils import getaddresses
from importlib.metadata import distributions
from typing import TYPE_CHECKING, Final, NotRequired, TypedDict

from hatchling.builders.utils import get_reproducible_timestamp
from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

if TYPE_CHECKING:
    from email.message import Message
    from importlib.metadata import Distribution, PackageMetadata


class OrganizationalEntity(TypedDict):
    """An organization that supplies or makes a component."""

    name: str
    url: list[str]


class Contact(TypedDict):
    name: NotRequired[str]
    email: NotRequired[str]


class _Hash(TypedDict):
    alg: str
    content: str


class Property(TypedDict):
    """A name and value pair; names this package writes start with the project name or ``python:``."""

    name: str
    value: str


class ExternalReference(TypedDict):
    type: str
    url: str
    comment: NotRequired[str]


class LicenseInfo(TypedDict):
    id: NotRequired[str]
    name: NotRequired[str]
    acknowledgement: str


class License(TypedDict):
    license: NotRequired[LicenseInfo]
    expression: NotRequired[str]
    acknowledgement: NotRequired[str]


class _Method(TypedDict):
    technique: str
    confidence: int
    value: str


class _Identity(TypedDict):
    field: str
    confidence: int
    methods: list[_Method]


class _Evidence(TypedDict):
    identity: list[_Identity]


#: A CycloneDX component: a distribution, an application, the interpreter or a file.
Component = TypedDict(
    "Component",
    {
        "type": str,
        "bom-ref": str,
        "name": str,
        "version": NotRequired[str],
        "purl": NotRequired[str],
        "supplier": NotRequired[OrganizationalEntity],
        "authors": NotRequired[list[Contact]],
        "description": NotRequired[str],
        "licenses": NotRequired[list[License]],
        "copyright": NotRequired[str],
        "hashes": NotRequired[list[_Hash]],
        "externalReferences": NotRequired[list[ExternalReference]],
        "properties": NotRequired[list[Property]],
        "evidence": NotRequired[_Evidence],
        "components": NotRequired[list["Component"]],
    },
)


class Dependency(TypedDict):
    """The components one component depends on, by ``bom-ref``."""

    ref: str
    dependsOn: list[str]


class _Reference(TypedDict):
    ref: str


class _Output(TypedDict):
    type: str
    resource: _Reference


class _Input(TypedDict):
    environmentVars: list[Property]


_Workflow = TypedDict(
    "_Workflow",
    {
        "bom-ref": str,
        "uid": str,
        "name": str,
        "taskTypes": list[str],
        "resourceReferences": list[_Reference],
        "outputs": list[_Output],
        "inputs": list[_Input],
    },
)


_Formula = TypedDict("_Formula", {"bom-ref": str, "workflows": list[_Workflow]})


class Lifecycle(TypedDict):
    phase: str


class Tools(TypedDict):
    components: list[Component]


class Metadata(TypedDict):
    timestamp: str
    lifecycles: list[Lifecycle]
    tools: Tools
    manufacturer: NotRequired[OrganizationalEntity]
    authors: NotRequired[list[Contact]]
    supplier: NotRequired[OrganizationalEntity]
    component: Component
    licenses: NotRequired[list[License]]
    properties: NotRequired[list[Property]]


class Composition(TypedDict):
    aggregate: str
    dependencies: list[str]


class Body(TypedDict):
    """The content of a document, everything but the header :func:`document` adds."""

    metadata: Metadata
    components: list[Component]
    dependencies: list[Dependency]
    compositions: NotRequired[list[Composition]]
    formulation: list[_Formula]


#: A complete CycloneDX 1.6 JSON document.
Document = TypedDict(
    "Document",
    {
        "$schema": str,
        "bomFormat": str,
        "specVersion": str,
        "serialNumber": str,
        "version": int,
        "metadata": Metadata,
        "components": list[Component],
        "dependencies": list[Dependency],
        "compositions": NotRequired[list[Composition]],
        "formulation": list[_Formula],
    },
)

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


def document(body: Body, namespace: uuid.UUID) -> Document:
    """
    Add the CycloneDX 1.6 header to a document body.

    :param body: the metadata, components, dependencies and formulation
    :param namespace: UUID namespace of the serial number, one per project
    :returns: the document; its serial number derives from the body, so identical bodies share one

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
    Format the build time.

    :returns: ISO 8601 time from ``SOURCE_DATE_EPOCH``, or hatchling's fixed default when it is unset

    """
    return datetime.fromtimestamp(get_reproducible_timestamp(), tz=UTC).isoformat()


def build_tools() -> tuple[list[Component], list[Dependency]]:
    """
    Describe the running environment: the interpreter and every installed distribution.

    Nothing about the machine goes in, so the same toolchain yields the same record on any operating system. A
    pure-Python distribution lists its files with their hashes; a platform one does not, because its files differ per
    machine.

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
        component["bom-ref"] = f"tool:{component['bom-ref']}"
        if Parser().parsestr(distribution.read_text("WHEEL") or "")["Root-Is-Purelib"] == "true":
            component["components"] = [
                file_component(
                    component["bom-ref"], file.as_posix(), f"{file.hash.mode}={file.hash.value}", str(file.size)
                )
                for file in distribution.files or []
                # console-script launchers live outside site-packages and embed the environment's interpreter path in
                # their shebang, so their hash differs on every build; the installer metadata names the frontend that
                # set up the environment rather than the distribution
                if file.hash is not None
                and not file.as_posix().startswith("../")
                and not (
                    file.parent.suffix == ".dist-info" and file.name in {"INSTALLER", "REQUESTED", "direct_url.json"}
                )
            ]
        tools.append(component)
        tool_dependencies.append({"ref": component["bom-ref"], "dependsOn": _depends_on(distribution, installed)})
    return tools, tool_dependencies


def purl(name: str, version: str | None = None) -> str:
    return f"pkg:pypi/{canonicalize_name(name)}@{version}" if version else f"pkg:pypi/{canonicalize_name(name)}"


def component_from_metadata(metadata: PackageMetadata | Message, component_type: str) -> Component:
    """
    Describe a distribution from its core metadata.

    :param metadata: the distribution's ``METADATA``
    :param component_type: the CycloneDX component type, such as ``library``
    :returns: the component, with its purl as ``bom-ref``, licenses, Project-URL references and metadata properties

    """
    name, version = metadata["Name"], metadata["Version"]
    package = purl(name, version)
    component: Final[Component] = {"type": component_type, "bom-ref": package, "name": name, "version": version}
    component["purl"] = package
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
    # core metadata headers copied verbatim onto the component
    component["properties"] = [
        {"name": f"python:{header.lower()}", "value": value}
        for header in ("Requires-Python", "Requires-Dist", "Provides-Extra", "Classifier", "Keywords")
        for value in metadata.get_all(header, [])
    ]
    return component


def contacts(names: list[str], addresses: list[str]) -> list[Contact]:
    found: Final[list[Contact]] = [{"name": name} for name in names]
    for name, email in getaddresses(addresses):
        contact: Contact = {}
        if name:
            contact["name"] = name
        if email:
            contact["email"] = email
        found.append(contact)
    return found


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
    # only the license classifiers that name exactly one SPDX license; "BSD License" or "Apache Software License" leave
    # the version or variant open
    if identifier := {
        "ISC License (ISCL)": "ISC",
        "MIT License": "MIT",
        "MIT No Attribution License (MIT-0)": "MIT-0",
        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "Python Software Foundation License": "PSF-2.0",
        "The Unlicense (Unlicense)": "Unlicense",
    }.get(name):
        return identifier
    try:
        canonical = canonicalize_license_expression(name)
    except InvalidLicenseExpression:
        return None
    # a CycloneDX license id holds one entry of the SPDX license list, never an expression or a LicenseRef
    return canonical if re.fullmatch(r"[A-Za-z0-9.-]+", canonical) and not canonical.startswith("LicenseRef-") else None


def external_reference(label: str, url: str) -> ExternalReference:
    reference_type = _URL_LABEL_TO_REFERENCE_TYPE.get(re.sub(r"[^a-z]", "", label.lower()), "other")
    return {"type": reference_type, "url": url, "comment": f"Project-URL: {label}"}


def file_component(parent_ref: str, path: str, digest: str, size: str) -> Component:
    # RECORD stores "<algorithm>=<urlsafe base64 without padding>", CycloneDX wants lowercase hex
    algorithm, _, encoded = digest.partition("=")
    algorithms: Final[dict[str, str]] = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
    }
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    return {
        "type": "file",
        "bom-ref": f"{parent_ref}#{path}",
        "name": path,
        "hashes": [{"alg": algorithms[algorithm], "content": raw.hex()}],
        "properties": [{"name": "size", "value": size}],
    }


def _depends_on(distribution: Distribution, installed: dict[str, Distribution]) -> list[str]:
    refs = set()
    for requirement in map(Requirement, distribution.requires or []):
        if (requirement.marker is None or requirement.marker.evaluate()) and (
            dependency := installed.get(purl(requirement.name))
        ):
            refs.add(f"tool:{purl(dependency.metadata['Name'], dependency.version)}")
    return sorted(refs)


def record_digest(content: bytes) -> str:
    return f"sha256={base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()}"


__all__ = [
    "Body",
    "Component",
    "Composition",
    "Contact",
    "Dependency",
    "Document",
    "ExternalReference",
    "License",
    "LicenseInfo",
    "Lifecycle",
    "Metadata",
    "OrganizationalEntity",
    "Property",
    "Tools",
    "build_tools",
    "component_from_metadata",
    "contacts",
    "document",
    "external_reference",
    "file_component",
    "purl",
    "record_digest",
    "timestamp",
]
