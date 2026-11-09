"""Build the components for a distribution, a bundled wheel and a file."""

from __future__ import annotations

import re
from email.utils import getaddresses
from itertools import starmap
from typing import TYPE_CHECKING, Final

from packaging.utils import canonicalize_name

from ._graph import walk_components
from ._iri import iri_reference
from ._licenses import licenses
from ._names import purl, pypi_url, reference_type, sbom_property
from ._types import Dependency

if TYPE_CHECKING:
    from ._content import BundledWheelInfo
    from ._inputs import BundledWheel, RecordRow
    from ._metadata import CoreMetadata
    from ._types import Component, Contact, ExternalReference, Identity, Property


def bundled_wheel_component(wheel: BundledWheel, property_prefix: str, info: BundledWheelInfo) -> Component:
    component = component_from_metadata(wheel.metadata)
    mark_bundled(component, wheel.path, property_prefix, info)
    component["hashes"] = [{"alg": "SHA-256", "content": wheel.sha256}]
    component["externalReferences"] = [
        *component["externalReferences"],
        {"type": "distribution", "url": pypi_url(wheel.metadata.name, wheel.metadata.version)},
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
        child["properties"] = [
            *child["properties"],
            {"name": sbom_property(property_prefix, "vendored-manifest"), "value": source},
        ]
        child["evidence"] = {"identity": [_evidence("purl", "manifest-analysis", source)]}
        # a vendored .dist-info comes after pip's manifest line naming the same package, so its metadata wins; keyed on
        # the PEP 503 name, since the manifest and the .dist-info may spell it differently
        vendored[f"{canonicalize_name(child['name'])}=={child['version']}"] = child
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
        contacts = [
            *(_contact(name, "") for name in metadata.values(names)),
            *starmap(_contact, getaddresses(metadata.values(addresses))),
        ]
        if people := [contact for contact in contacts if contact]:
            component["authors"] = people
            break
    if declared := licenses(metadata):
        component["licenses"] = declared
    component["externalReferences"], unlinked = _project_references(metadata)
    # core metadata headers copied verbatim, so a reader sees what the distribution declared
    headers: Final[list[tuple[str, list[str]]]] = [
        ("requires-python", metadata.values("requires_python")),
        ("requires-dist", metadata.values("requires_dist")),
        ("provides-extra", metadata.values("provides_extra")),
        ("classifier", metadata.values("classifiers")),
        ("keywords", metadata.keywords()),
    ]
    component["properties"] = []
    for header, values in headers:
        component["properties"].extend({"name": f"python:{header}", "value": value} for value in values)
    component["properties"].extend(unlinked)
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


def _project_references(metadata: CoreMetadata) -> tuple[list[ExternalReference], list[Property]]:
    # a URL CycloneDX would reject is percent-encoded where that keeps what it points at and left out where it cannot
    # be, as an scp-style git address; either way the header's text is kept verbatim as a property
    references: Final[list[ExternalReference]] = []
    unlinked: Final[list[Property]] = []
    # a home page that is not an http(s) URL, such as UNKNOWN, is left out
    if (home_page := metadata.first("home_page")) and re.match(r"https?:", home_page, re.IGNORECASE):
        if (url := iri_reference(home_page)) is not None:
            references.append({"type": "website", "url": url})
        if url != home_page:
            unlinked.append({"name": "python:home-page", "value": home_page})
    for label, link in metadata.project_urls():
        if (url := iri_reference(link)) is not None:
            references.append({"type": reference_type(label), "url": url, "comment": f"Project-URL: {label}"})
        if url != link:
            unlinked.append({"name": "python:project-url", "value": f"{label}, {link}"})
    return references, unlinked


def mark_bundled(component: Component, path: str, property_prefix: str, info: BundledWheelInfo) -> None:
    # the purl names the package; the path, of a .whl or of the directory a wheel is unpacked into, tells apart copies
    # of one release bundled in two places
    component["bom-ref"] = f"bundled:{path}"
    if info.supplier is not None:
        component["supplier"] = info.supplier
    component["properties"] = [
        {"name": sbom_property(property_prefix, "bundled-wheel"), "value": path},
        *info.properties,
        *component["properties"],
    ]


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


__all__ = [
    "bundled_wheel_component",
    "component_from_metadata",
    "file_component",
    "mark_bundled",
    "vendored_dependencies",
]
