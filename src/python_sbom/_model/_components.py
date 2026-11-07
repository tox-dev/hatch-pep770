from __future__ import annotations

import hashlib
import re
from email.utils import getaddresses
from itertools import starmap
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from ._inputs import RecordRow
from ._licenses import licenses
from ._names import project_urls, property_prefix, purl, pypi_url, reference_type, tool_ref
from ._types import Dependency

if TYPE_CHECKING:
    from email.message import Message
    from importlib.metadata import PackageMetadata
    from pathlib import PurePosixPath

    from ._inputs import BundledWheel
    from ._types import Component, Contact, ExternalReference, Identity, OrganizationalEntity, Property


def bundled_wheel_component(
    wheel: BundledWheel, namespace: str, properties: list[Property], supplier: OrganizationalEntity | None
) -> Component:
    component = component_from_metadata(wheel.metadata)
    # the purl names the package; the path tells apart copies of one release bundled in two places
    component["bom-ref"] = f"bundled:{wheel.path}"
    if supplier is not None:
        component["supplier"] = supplier
    component["hashes"] = [{"alg": "SHA-256", "content": wheel.sha256}]
    component["externalReferences"] = [
        *component["externalReferences"],
        {"type": "distribution", "url": pypi_url(wheel.metadata["Name"], wheel.metadata["Version"])},
    ]
    component["properties"] = [
        {"name": f"{namespace}:bundled-wheel", "value": wheel.path},
        *properties,
        *component["properties"],
    ]
    component["evidence"] = {
        "identity": [
            _evidence("purl", "manifest-analysis", wheel.metadata_name),
            _evidence("hash", "hash-comparison", wheel.sha256),
        ]
    }
    vendored: Final[dict[str, Component]] = {}
    for source, metadata in wheel.vendored:
        child = component_from_metadata(metadata)
        child["bom-ref"] = f"{component['bom-ref']}#vendored/{child['bom-ref']}"
        child["properties"] = [*child["properties"], {"name": f"{namespace}:vendored-manifest", "value": source}]
        child["evidence"] = {"identity": [_evidence("purl", "manifest-analysis", source)]}
        # a vendored .dist-info comes after pip's manifest line naming the same package, so its metadata wins; keyed on
        # the PEP 503 name, since the manifest and the .dist-info may spell it differently
        vendored[f"{property_prefix(child['name'])}=={child['version']}"] = child
    component["components"] = [
        *(file_component(component["bom-ref"], row) for row in wheel.files),
        *(vendored[key] for key in sorted(vendored)),
    ]
    return component


def component_from_metadata(metadata: PackageMetadata | Message) -> Component:
    name, version = metadata["Name"], metadata["Version"]
    component: Final[Component] = {"type": "library", "bom-ref": purl(name, version), "name": name, "version": version}
    component["purl"] = component["bom-ref"]
    if summary := metadata.get("Summary"):
        component["description"] = summary
    # maintainers are who users reach today, so they win over the original authors when both are named
    for names, addresses in (("Maintainer", "Maintainer-email"), ("Author", "Author-email")):
        named = (_contact(name, "") for name in metadata.get_all(names, []))
        if people := [
            contact
            for contact in (*named, *starmap(_contact, getaddresses(metadata.get_all(addresses, []))))
            if contact
        ]:
            component["authors"] = people
            break
    if declared := licenses(metadata):
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


def _evidence(field: str, technique: str, value: str) -> Identity:
    return {"field": field, "confidence": 1, "methods": [{"technique": technique, "confidence": 1, "value": value}]}


def file_component(parent_ref: str, row: RecordRow) -> Component:
    return {
        "type": "file",
        "bom-ref": f"{parent_ref}#{row.path}",
        "name": row.path,
        "hashes": [{"alg": row.algorithm, "content": row.digest}],
        "properties": [{"name": "size", "value": row.size}],
    }


def vendored_dependencies(components: list[Component]) -> list[Dependency]:
    # each bundled wheel depends on the packages it vendors, wherever it sits in the document
    found: Final[list[Dependency]] = []
    pending = list(components)
    while pending:
        component = pending.pop(0)
        children = component.get("components", [])
        if component["bom-ref"].startswith("bundled:") and (
            vendored := [
                child["bom-ref"]
                for child in children
                if child["type"] == "library" and "#vendored/" in child["bom-ref"]
            ]
        ):
            found.append(Dependency(ref=component["bom-ref"], dependsOn=vendored))
        pending.extend(children)
    return found


def file_component_from_bytes(parent_ref: str, name: str, content: bytes) -> Component:
    return file_component(
        parent_ref,
        RecordRow(path=name, algorithm="SHA-256", digest=hashlib.sha256(content).hexdigest(), size=str(len(content))),
    )


def script_tool(path: PurePosixPath, sha256: str, version: str, link: str | None) -> Component:
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


__all__ = [
    "bundled_wheel_component",
    "component_from_metadata",
    "file_component",
    "file_component_from_bytes",
    "script_tool",
    "vendored_dependencies",
]
