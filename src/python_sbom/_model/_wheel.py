from __future__ import annotations

import csv
import uuid
from dataclasses import dataclass
from io import StringIO
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final
from urllib.parse import quote, urlsplit

from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from ._components import component_from_metadata, contacts, document, external_reference, file_component, purl

if TYPE_CHECKING:
    from collections.abc import Sequence
    from email.message import Message

    from python_sbom._collect._facts import BuildFacts
    from python_sbom._collect._settings import Settings
    from python_sbom._collect._source import BuildScript, BundledWheel, SourceTree

    from ._types import Component, Contact, Dependency, Document, ExternalReference, License, Property


@dataclass(frozen=True, slots=True, kw_only=True)
class WheelInputs:
    # Everything the document of one wheel is built from, gathered beforehand.
    metadata: Message
    wheel_name: str
    settings: Settings
    facts: BuildFacts
    source: SourceTree


def describe(inputs: WheelInputs) -> Document:
    metadata, settings = inputs.metadata, inputs.settings
    namespace = canonicalize_name(metadata["Name"])
    repository = settings.repository or next(
        (
            url.strip().rstrip("/")
            for label, url in (entry.split(",", 1) for entry in metadata.get_all("Project-URL", []))
            if external_reference(label.strip(), url.strip())["type"] == "vcs"
        ),
        None,
    )
    directories = " and ".join(sorted({str(PurePosixPath(pattern).parent) for pattern in settings.bundled_wheels}))
    scope = (
        f"Components are the wheels bundled as data files under {directories} and the direct runtime dependencies"
        " declared in the wheel's core metadata. The latter carry no version because they are resolved at install"
        " time, not at build time."
        if directories
        else "Components are the direct runtime dependencies declared in the wheel's core metadata. They carry no"
        " version because they are resolved at install time, not at build time."
    )
    root = _root_component(inputs, repository)
    bundled = [_bundled_component(wheel, namespace, settings, repository) for wheel in inputs.source.bundled]
    declared = [_declared_dependency(requirement, namespace) for requirement in _runtime_requirements(metadata)]
    bundled_dependencies: Final[list[Dependency]] = [
        {"ref": component["bom-ref"], "dependsOn": references}
        for component in bundled
        if (references := [child["bom-ref"] for child in component["components"] if child["type"] == "library"])
    ]
    tools: Final[list[Component]] = list(inputs.facts.tools)
    if (script := inputs.source.build_script) is not None:
        tools.insert(0, _build_script_tool(script, metadata["Version"], settings, repository))
    authors = _authors(metadata)
    licenses = _licenses(metadata)
    return document(
        {
            "metadata": {
                "timestamp": inputs.facts.timestamp,
                "lifecycles": [{"phase": "build"}],
                "tools": {"components": tools},
                **({"manufacturer": settings.supplier} if settings.supplier else {}),
                **({"authors": authors} if authors else {}),
                **({"supplier": settings.supplier} if settings.supplier else {}),
                "component": root,
                **({"licenses": licenses} if licenses else {}),
                "properties": [{"name": f"{namespace}:sbom:scope", "value": scope}],
            },
            "components": [*bundled, *declared],
            "dependencies": [
                {"ref": root["bom-ref"], "dependsOn": [component["bom-ref"] for component in [*bundled, *declared]]},
                *bundled_dependencies,
                *inputs.facts.tool_dependencies,
            ],
            # transitive runtime dependencies are unknown until install time
            "compositions": [{"aggregate": "incomplete", "dependencies": [root["bom-ref"]]}],
            "formulation": [
                {
                    "bom-ref": "formula:wheel-build",
                    "workflows": [
                        {
                            "bom-ref": "workflow:wheel-build",
                            "uid": "wheel-build",
                            "name": "build the wheel and this SBOM",
                            "taskTypes": ["build"],
                            "resourceReferences": [{"ref": tool["bom-ref"]} for tool in tools],
                            "outputs": [{"type": "artifact", "resource": {"ref": root["bom-ref"]}}],
                            "inputs": [
                                {"environmentVars": [{"name": "SOURCE_DATE_EPOCH", "value": str(inputs.facts.epoch)}]}
                            ],
                        }
                    ],
                }
            ],
        },
        uuid.uuid5(uuid.NAMESPACE_URL, f"{repository or f'https://pypi.org/project/{namespace}'}/sboms"),
    )


def _root_component(inputs: WheelInputs, repository: str | None) -> Component:
    metadata, settings = inputs.metadata, inputs.settings
    name, version = metadata["Name"], metadata["Version"]
    namespace = canonicalize_name(name)
    references: Final[list[ExternalReference]] = [
        external_reference(label.strip(), url.strip())
        for label, url in (entry.split(",", 1) for entry in metadata.get_all("Project-URL", []))
    ]
    references.extend([
        {"type": "distribution", "url": f"https://pypi.org/project/{name}/{version}/"},
        {
            "type": "attestation",
            "url": f"https://pypi.org/integrity/{name}/{version}/{inputs.wheel_name}/provenance",
        },
    ])
    if repository and urlsplit(repository).netloc == "github.com":
        references.extend([
            {"type": "security-contact", "url": f"{repository}/security/policy"},
            {"type": "advisories", "url": f"{repository}/security/advisories"},
        ])
    license_files: Final[list[str]] = metadata.get_all("License-File", [])
    if repository and license_files:
        references.append({"type": "license", "url": f"{repository}/blob/{settings.default_branch}/{license_files[0]}"})
    properties: Final[list[Property]] = []
    if requires_python := metadata.get("Requires-Python"):
        properties.append({"name": f"{namespace}:requires-python", "value": requires_python})
    properties.extend({"name": "python:classifier", "value": value} for value in metadata.get_all("Classifier", []))
    properties.extend(
        {"name": "python:keyword", "value": keyword.strip()}
        for keyword in (metadata.get("Keywords") or "").split(",")
        if keyword.strip()
    )
    if commit := inputs.facts.commit:
        if repository:
            references.append({"type": "vcs", "url": f"{repository}/tree/{commit}", "comment": "exact source revision"})
        properties.append({"name": f"{namespace}:vcs-commit", "value": commit})
    authors = _authors(metadata)
    licenses = _licenses(metadata)
    package = purl(name, version)
    return {
        "type": "application",
        "bom-ref": package,
        **({"supplier": settings.supplier} if settings.supplier else {}),
        **({"authors": authors} if authors else {}),
        "name": name,
        "version": version,
        **({"description": summary} if (summary := metadata.get("Summary")) else {}),
        **({"licenses": licenses} if licenses else {}),
        **({"copyright": inputs.source.copyright} if inputs.source.copyright else {}),
        "purl": package,
        "externalReferences": references,
        "properties": properties,
    }


def _bundled_component(wheel: BundledWheel, namespace: str, settings: Settings, repository: str | None) -> Component:
    component = component_from_metadata(wheel.metadata, "library")
    # the purl names the package; two variants of one release, such as per-platform wheels, are told apart by file
    component["bom-ref"] = f"{component['bom-ref']}?file_name={quote(PurePosixPath(wheel.path).name)}"
    # a bundled wheel published from the same forge account as this project shares its supplier
    if (
        settings.supplier
        and repository
        and any(reference["url"].startswith(_owner(repository)) for reference in component["externalReferences"])
    ):
        component["supplier"] = settings.supplier
    component["hashes"] = [{"alg": "SHA-256", "content": wheel.sha256}]
    component["externalReferences"].append({
        "type": "distribution",
        "url": f"https://pypi.org/project/{wheel.metadata['Name']}/{wheel.metadata['Version']}/",
    })
    component["properties"] = [
        {"name": f"{namespace}:bundled-wheel", "value": wheel.path},
        *wheel.extra_properties,
        *component["properties"],
    ]
    component["evidence"] = {
        "identity": [
            {
                "field": "purl",
                "confidence": 1,
                "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": wheel.metadata_name}],
            },
            {
                "field": "hash",
                "confidence": 1,
                "methods": [{"technique": "hash-comparison", "confidence": 1, "value": wheel.sha256}],
            },
        ],
    }
    component["components"] = [
        file_component(component["bom-ref"], path, digest, size)
        for path, digest, size in (row for row in csv.reader(StringIO(wheel.record, newline="")) if row)
        if digest
    ]
    children: Final[dict[str, Component]] = {}
    for source, child_metadata in wheel.vendored:
        child = component_from_metadata(child_metadata, "library")
        child["bom-ref"] = f"{component['bom-ref']}#vendored/{child['bom-ref']}"
        child["properties"].append({"name": f"{namespace}:vendored-manifest", "value": source})
        child["evidence"] = {
            "identity": [
                {
                    "field": "purl",
                    "confidence": 1,
                    "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": source}],
                }
            ],
        }
        # a vendored .dist-info comes after the pip manifest line naming the same purl, so its metadata wins
        children[purl(child["name"], child["version"])] = child
    component["components"].extend(children[key] for key in sorted(children))
    return component


def _owner(repository: str) -> str:
    parts = urlsplit(repository)
    return f"{parts.scheme}://{parts.netloc}/{parts.path.strip('/').split('/')[0]}/"


def _declared_dependency(requirement: str, namespace: str) -> Component:
    parsed = Requirement(requirement)
    component: Final[Component] = {
        "type": "library",
        # the same distribution can be declared more than once with different markers, so the purl is not unique
        "bom-ref": f"requires-dist:{requirement}",
        "name": parsed.name,
        "purl": purl(parsed.name),
        "externalReferences": [{"type": "distribution", "url": f"https://pypi.org/project/{parsed.name}/"}],
        "properties": [{"name": f"{namespace}:requires-dist", "value": requirement}],
    }
    if parsed.marker is not None:
        component["properties"].append({"name": f"{namespace}:environment-marker", "value": str(parsed.marker)})
    return component


def _runtime_requirements(metadata: Message) -> list[str]:
    # a requirement belongs to the wheel's runtime dependencies when it can apply with no extra requested
    return [
        requirement
        for requirement in metadata.get_all("Requires-Dist", [])
        if (marker := Requirement(requirement).marker) is None or _without_extras(marker) is not False
    ]


def _without_extras(marker: Marker) -> bool | None:
    # three-valued: an extra condition is decided with no extra requested, any other stays unknown, so a requirement
    # is kept unless its extra conditions alone rule it out; packaging exposes the parsed tree only privately
    return _any_of(marker._markers)  # ruff: ignore[private-member-access]  # no public marker tree


def _any_of(
    markers: Sequence[object],  # simplint: ignore[SMP602]  # packaging's private tree is untyped
) -> bool | None:
    # "and" binds tighter than "or", as in packaging's own evaluation
    groups: Final[list[list[bool | None]]] = [[]]
    for item in markers:
        if item == "or":
            groups.append([])
        elif isinstance(item, list):
            groups[-1].append(_any_of(item))
        elif isinstance(item, tuple):  # skips "and", which grouping already applies
            groups[-1].append(_atom(item))
    verdicts = [False if False in group else (None if None in group else True) for group in groups]
    return True if True in verdicts else (None if None in verdicts else False)


def _atom(item: tuple[object, ...]) -> bool | None:  # simplint: ignore[SMP602]  # packaging's private tree
    kinds = [type(part).__name__ for part in item]
    left, operator, right = (str(part) for part in item)
    if kinds[0] == "Variable" and left == "extra":
        return Marker(f"extra {operator} {right!r}").evaluate({"extra": ""})
    if kinds[2] == "Variable" and right == "extra":
        return Marker(f"{left!r} {operator} extra").evaluate({"extra": ""})
    return None


def _build_script_tool(script: BuildScript, version: str, settings: Settings, repository: str | None) -> Component:
    tool: Final[Component] = {
        "type": "application",
        "bom-ref": f"tool:{script.path}",
        "name": script.path.name,
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": script.sha256}],
    }
    if repository:
        tool["externalReferences"] = [
            {"type": "vcs", "url": f"{repository}/blob/{settings.default_branch}/{script.path}"}
        ]
    return tool


def _authors(metadata: Message) -> list[Contact]:
    # core metadata joins several names into one header
    if people := contacts(
        [name for entry in metadata.get_all("Maintainer", []) for name in entry.split(", ")],
        metadata.get_all("Maintainer-email", []),
    ):
        return people
    return contacts(
        [name for entry in metadata.get_all("Author", []) for name in entry.split(", ")],
        metadata.get_all("Author-email", []),
    )


def _licenses(metadata: Message) -> list[License]:
    if expression := metadata.get("License-Expression"):
        return [{"expression": expression, "acknowledgement": "declared"}]
    return []


__all__ = [
    "WheelInputs",
    "describe",
]
