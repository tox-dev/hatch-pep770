from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from email.utils import getaddresses
from typing import TYPE_CHECKING, Final

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.utils import canonicalize_name

if TYPE_CHECKING:
    from email.message import Message
    from importlib.metadata import PackageMetadata

    from ._types import Body, Component, Contact, Document, ExternalReference, License


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


def purl(name: str, version: str | None = None) -> str:
    return f"pkg:pypi/{canonicalize_name(name)}@{version}" if version else f"pkg:pypi/{canonicalize_name(name)}"


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


def record_digest(content: bytes) -> str:
    return f"sha256={base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()}"


__all__ = [
    "component_from_metadata",
    "contacts",
    "document",
    "external_reference",
    "file_component",
    "purl",
    "record_digest",
]
