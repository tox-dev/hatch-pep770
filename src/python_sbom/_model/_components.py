from __future__ import annotations

import re
from email.utils import getaddresses
from itertools import starmap
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from ._document import walk_components
from ._licenses import licenses
from ._names import property_prefix, purl, pypi_url, reference_type, tool_ref
from ._types import Dependency

if TYPE_CHECKING:
    from pathlib import PurePosixPath

    from ._inputs import BundledWheel, RecordRow
    from ._metadata import CoreMetadata
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
        {"type": "distribution", "url": pypi_url(wheel.metadata.name, wheel.metadata.version)},
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


def component_from_metadata(metadata: CoreMetadata) -> Component:
    name, version = metadata.name, metadata.version
    component: Final[Component] = {"type": "library", "bom-ref": purl(name, version), "name": name, "version": version}
    component["purl"] = component["bom-ref"]
    if summary := metadata.first("summary"):
        component["description"] = summary
    # maintainers are who users reach today, so they win over the original authors when both are named
    for names, addresses in (("maintainer", "maintainer_email"), ("author", "author_email")):
        named = (_contact(name, "") for name in metadata.values(names))
        if people := [
            contact for contact in (*named, *starmap(_contact, getaddresses(metadata.values(addresses)))) if contact
        ]:
            component["authors"] = people
            break
    if declared := licenses(metadata):
        component["licenses"] = declared
    component["externalReferences"] = _project_references(metadata)
    # core metadata headers copied verbatim, so a reader sees what the distribution declared
    component["properties"] = [
        {"name": f"python:{header}", "value": value}
        for header, values in (
            ("requires-python", metadata.values("requires_python")),
            ("requires-dist", metadata.values("requires_dist")),
            ("provides-extra", metadata.values("provides_extra")),
            ("classifier", metadata.values("classifiers")),
            ("keywords", metadata.keywords()),
        )
        for value in values
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


def _project_references(metadata: CoreMetadata) -> list[ExternalReference]:
    # a home page that is not an http(s) URL, such as UNKNOWN, is left out
    references: Final[list[ExternalReference]] = []
    if (home_page := metadata.first("home_page")) and urlsplit(home_page).scheme in {"http", "https"}:
        references.append({"type": "website", "url": home_page})
    references.extend(
        {"type": reference_type(label), "url": url, "comment": f"Project-URL: {label}"}
        for label, url in metadata.project_urls()
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
    for component in walk_components(components):
        if not component["bom-ref"].startswith("bundled:"):
            continue
        # a file's ref holds its path, which may itself hold "#vendored/"
        libraries = (child["bom-ref"] for child in component.get("components", []) if child["type"] == "library")
        if vendored := [ref for ref in libraries if "#vendored/" in ref]:
            found.append(Dependency(ref=component["bom-ref"], dependsOn=vendored))
    return found


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
    "script_tool",
    "vendored_dependencies",
]
