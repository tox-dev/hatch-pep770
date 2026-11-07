from __future__ import annotations

import hashlib
import re
from email.utils import getaddresses
from itertools import starmap
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.utils import canonicalize_name

if TYPE_CHECKING:
    from email.message import Message
    from importlib.metadata import PackageMetadata
    from pathlib import PurePosixPath

    from ._inputs import BundledWheel, BundledWheelInfo, RecordRow
    from ._types import Component, Contact, ExternalReference, Identity, License

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


def bundled_wheel_component(wheel: BundledWheel, namespace: str, info: BundledWheelInfo) -> Component:
    """
    Describe a wheel a project ships as a data file.

    :param wheel: the wheel, as :func:`~python_sbom.read_bundled_wheel` read it
    :param namespace: the project's normalized name, which prefixes the properties this package writes
    :param info: what the project adds to the component
    :returns: the component, with a file component per ``RECORD`` row and a component per vendored package

    """
    component = component_from_metadata(wheel.metadata)
    # the purl names the package; the path tells apart copies of one release bundled in two places
    component["bom-ref"] = f"bundled:{wheel.path}"
    if info.supplier is not None:
        component["supplier"] = info.supplier
    component["hashes"] = [{"alg": "SHA-256", "content": wheel.sha256}]
    component["externalReferences"] = [
        *component["externalReferences"],
        {"type": "distribution", "url": pypi_url(wheel.metadata["Name"], wheel.metadata["Version"])},
    ]
    component["properties"] = [
        {"name": f"{namespace}:bundled-wheel", "value": wheel.path},
        *info.properties,
        *component["properties"],
    ]
    component["evidence"] = {
        "identity": [
            _identity("purl", "manifest-analysis", wheel.metadata_name),
            _identity("hash", "hash-comparison", wheel.sha256),
        ]
    }
    vendored: Final[dict[str, Component]] = {}
    for source, metadata in wheel.vendored:
        child = component_from_metadata(metadata)
        child["bom-ref"] = f"{component['bom-ref']}#vendored/{child['bom-ref']}"
        child["properties"] = [*child["properties"], {"name": f"{namespace}:vendored-manifest", "value": source}]
        child["evidence"] = {"identity": [_identity("purl", "manifest-analysis", source)]}
        # a vendored .dist-info comes after pip's manifest line naming the same package, so its metadata wins
        vendored[purl(child["name"], child["version"])] = child
    component["components"] = [
        *(file_component(component["bom-ref"], row) for row in wheel.files),
        *(vendored[key] for key in sorted(vendored)),
    ]
    return component


def component_from_metadata(metadata: PackageMetadata | Message) -> Component:
    """
    Describe a distribution from its core metadata, as a ``library`` component.

    :param metadata: the distribution's ``METADATA``
    :returns: the component, with its purl as ``bom-ref``, authors, licenses, project URLs and metadata properties

    """
    name, version = metadata["Name"], metadata["Version"]
    component: Final[Component] = {"type": "library", "bom-ref": purl(name, version), "name": name, "version": version}
    component["purl"] = component["bom-ref"]
    if summary := metadata.get("Summary"):
        component["description"] = summary
    # maintainers are who users reach today, so they win over the original authors when both are named
    if people := next(
        (
            found
            for names, addresses in (("Maintainer", "Maintainer-email"), ("Author", "Author-email"))
            if (
                found := [
                    contact
                    for contact in (
                        *(_contact(name, "") for name in metadata.get_all(names, [])),
                        *starmap(_contact, getaddresses(metadata.get_all(addresses, []))),
                    )
                    if contact
                ]
            )
        ),
        None,
    ):
        component["authors"] = people
    if declared := _licenses(metadata):
        component["licenses"] = declared
    component["externalReferences"] = _project_references(metadata)
    # core metadata headers copied verbatim, so a reader sees what the distribution declared
    component["properties"] = [
        {"name": f"python:{header.lower()}", "value": value}
        for header in ("Requires-Python", "Requires-Dist", "Provides-Extra", "Classifier", "Keywords")
        for value in metadata.get_all(header, [])
    ]
    return component


def _contact(name: str, email: str) -> Contact:
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        # an address the schema rejects as an email, such as "jane at example.com", is kept as the name
        return {"name": " ".join(part for part in (name, email) if part)}
    contact: Final[Contact] = {}
    if name:
        contact["name"] = name
    if email:
        contact["email"] = email
    return contact


def _licenses(metadata: PackageMetadata | Message) -> list[License]:
    # a License-Expression is taken as declared; otherwise each License field and License classifier name is
    # declared, and the SPDX ids they map to are added as concluded
    if expression := metadata.get("License-Expression"):
        return [{"expression": expression, "acknowledgement": "declared"}]
    names = [
        entry.rsplit(" :: ", 1)[-1] for entry in metadata.get_all("Classifier", []) if entry.startswith("License :: ")
    ]
    if (declared := metadata.get("License")) and "\n" not in declared:
        names.append(declared)
    found: Final[list[License]] = [{"license": {"name": name, "acknowledgement": "declared"}} for name in names]
    # a license policy judges SPDX ids only, so the names stay bare when any one of them does not resolve, and the
    # policy reports that instead of judging a partial set
    identifiers = [identifier for name in names if (identifier := _spdx_license(name)) is not None]
    if len(identifiers) == len(names):
        found.extend(
            {"license": {"id": identifier, "acknowledgement": "concluded"}} for identifier in dict.fromkeys(identifiers)
        )
    return found


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


def _project_references(metadata: PackageMetadata | Message) -> list[ExternalReference]:
    # a home page that is not an http(s) URL, such as UNKNOWN, is left out
    references: Final[list[ExternalReference]] = []
    if (home_page := metadata.get("Home-page")) and urlsplit(home_page).scheme in {"http", "https"}:
        references.append({"type": "website", "url": home_page})
    references.extend(
        {"type": reference_type(label), "url": url, "comment": f"Project-URL: {label}"}
        for label, url in project_urls(metadata)
    )
    return references


def reference_type(label: str) -> str:
    return _URL_LABEL_TO_REFERENCE_TYPE.get(re.sub(r"[^a-z]", "", label.lower()), "other")


def project_urls(metadata: PackageMetadata | Message) -> list[tuple[str, str]]:
    return [
        (label.strip(), url.strip())
        for label, url in (entry.split(",", 1) for entry in metadata.get_all("Project-URL", []) if "," in entry)
    ]


def pypi_url(name: str, version: str | None = None) -> str:
    return f"https://pypi.org/project/{name}/{version}/" if version else f"https://pypi.org/project/{name}/"


def _identity(field: str, technique: str, value: str) -> Identity:
    return {"field": field, "confidence": 1, "methods": [{"technique": technique, "confidence": 1, "value": value}]}


def purl(name: str, version: str | None = None) -> str:
    return f"pkg:pypi/{canonicalize_name(name)}@{version}" if version else f"pkg:pypi/{canonicalize_name(name)}"


def file_component(parent_ref: str, row: RecordRow) -> Component:
    return {
        "type": "file",
        "bom-ref": f"{parent_ref}#{row.path}",
        "name": row.path,
        "hashes": [{"alg": row.algorithm, "content": row.digest}],
        "properties": [{"name": "size", "value": row.size}],
    }


def file_component_from_bytes(parent_ref: str, name: str, content: bytes) -> Component:
    """
    Describe one file from its bytes, such as a member of a zipapp.

    :param parent_ref: the ``bom-ref`` of the component that holds the file
    :param name: the file's path
    :param content: the file's bytes
    :returns: a ``file`` component with the file's SHA-256 and size

    """
    return {
        "type": "file",
        "bom-ref": f"{parent_ref}#{name}",
        "name": name,
        "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(content).hexdigest()}],
        "properties": [{"name": "size", "value": str(len(content))}],
    }


def script_tool(path: PurePosixPath, sha256: str, version: str, link: str | None) -> Component:
    """
    Describe a build script as a build tool, since a rebuild has to match the script that shaped the document.

    :param path: the script's path relative to the project root
    :param sha256: the SHA-256 of the script
    :param version: the version of the artifact the script builds
    :param link: a URL of the script in the repository, or ``None``
    :returns: an ``application`` component

    """
    tool: Final[Component] = {
        "type": "application",
        "bom-ref": tool_ref(str(path)),
        "name": path.name,
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": sha256}],
    }
    if link is not None:
        tool["externalReferences"] = [{"type": "vcs", "url": link}]
    return tool


def tool_ref(ref: str) -> str:
    # prefixed because the same distribution can be both a build tool and a component of the artifact
    return f"tool:{ref}"


def sbom_file_name(name: str) -> str:
    return f"{canonicalize_name(name)}.cdx.json"


__all__ = [
    "bundled_wheel_component",
    "component_from_metadata",
    "file_component",
    "file_component_from_bytes",
    "project_urls",
    "purl",
    "pypi_url",
    "reference_type",
    "sbom_file_name",
    "script_tool",
    "tool_ref",
]
