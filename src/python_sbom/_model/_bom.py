from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from packaging.requirements import Requirement

from ._components import bundled_wheel_component, component_from_metadata, script_tool, vendored_dependencies
from ._document import contributed_properties, formulation, timestamp, with_header
from ._identity import project_identity
from ._markers import applies_without_extras
from ._names import SBOM_FILE, SBOM_REPOSITORY, purl, pypi_url, sbom_file_name, sbom_property
from ._tools import tool_components

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._identity import ProjectIdentity
    from ._inputs import BuildFacts, BundledWheelInfo, Contributions, SbomRequest, Settings, SourceTree
    from ._types import Component, Document, ExternalReference, Metadata, Property


def describe(
    request: SbomRequest,
    source: SourceTree,
    facts: BuildFacts,
    bundled_info: Mapping[str, BundledWheelInfo],
    contributions: Contributions,
) -> Document:
    project = project_identity(request.metadata, request.settings)
    root = _root_component(request, source, facts, project, contributions)
    bundled = [
        bundled_wheel_component(
            wheel,
            project.property_prefix,
            bundled_info[wheel.path].properties,
            bundled_info[wheel.path].supplier,
        )
        for wheel in source.bundled
    ]
    components = [
        *bundled,
        # hatchling repeats a Requires-Dist when a hook re-adds a dependency, and each bom-ref must be unique
        *(
            _declared_dependency(text, requirement, project.property_prefix)
            for text in dict.fromkeys(request.metadata.values("requires_dist"))
            if applies_without_extras(requirement := Requirement(text))
        ),
        *contributions.components,
    ]
    environment, tool_dependencies = tool_components(facts)
    tools = [
        *(
            script_tool(
                script.path,
                script.sha256,
                request.metadata.version,
                _file_link(project, request.settings, str(script.path)),
            )
            for script in source.build_scripts
        ),
        *environment,
        *contributions.tools,
    ]
    return with_header(
        {
            "metadata": _metadata(root, tools, request, project, facts),
            "components": components,
            "dependencies": [
                {"ref": root["bom-ref"], "dependsOn": [component["bom-ref"] for component in components]},
                *vendored_dependencies(bundled),
                *tool_dependencies,
                *contributions.dependencies,
            ],
            # transitive runtime dependencies are unknown until install time
            "compositions": [{"aggregate": "incomplete", "dependencies": [root["bom-ref"]]}],
            "formulation": [formulation("wheel-build", "build the wheel and this SBOM", tools, root["bom-ref"], facts)],
        },
        project.serial_namespace,
    )


def _root_component(
    request: SbomRequest, source: SourceTree, facts: BuildFacts, project: ProjectIdentity, contributions: Contributions
) -> Component:
    metadata, settings = request.metadata, request.settings
    name, version = metadata.name, metadata.version
    root = component_from_metadata(metadata)
    root["type"] = "application"
    if settings.supplier is not None:
        root["supplier"] = settings.supplier
    if source.copyright is not None:
        root["copyright"] = source.copyright
    references: Final[list[ExternalReference]] = [
        *root["externalReferences"],
        {"type": "distribution", "url": pypi_url(name, version)},
        {"type": "attestation", "url": f"https://pypi.org/integrity/{name}/{version}/{request.wheel_name}/provenance"},
    ]
    if project.repository and urlsplit(project.repository).netloc == "github.com":
        references.extend([
            {"type": "security-contact", "url": f"{project.repository}/security/policy"},
            {"type": "advisories", "url": f"{project.repository}/security/advisories"},
        ])
    if (license_files := metadata.values("license_files")) and (
        link := _file_link(project, settings, license_files[0])
    ):
        references.append({"type": "license", "url": link})
    properties: Final[list[Property]] = [
        *root["properties"],
        *contributed_properties(contributions.root_properties, project.property_prefix),
    ]
    if (revision := facts.revision) is not None:
        if project.repository:
            comment = "source revision, with uncommitted changes" if revision.dirty else "exact source revision"
            references.append({
                "type": "vcs",
                "url": f"{project.repository}/tree/{revision.commit}",
                "comment": comment,
            })
        properties.append({"name": f"{project.property_prefix}:vcs-commit", "value": revision.commit})
        if revision.dirty:
            properties.append({"name": f"{project.property_prefix}:vcs-dirty", "value": "true"})
    root["externalReferences"] = references
    root["properties"] = properties
    return root


def _declared_dependency(text: str, requirement: Requirement, namespace: str) -> Component:
    component: Final[Component] = {
        "type": "library",
        # the same distribution can be declared more than once with different markers, so the purl is not unique
        "bom-ref": f"requires-dist:{text}",
        "name": requirement.name,
        "purl": purl(requirement.name),
        "externalReferences": [{"type": "distribution", "url": pypi_url(requirement.name)}],
        "properties": [{"name": f"{namespace}:requires-dist", "value": text}],
    }
    if requirement.marker is not None:
        component["properties"].append({"name": f"{namespace}:environment-marker", "value": str(requirement.marker)})
    return component


def _file_link(project: ProjectIdentity, settings: Settings, path: str) -> str | None:
    return None if project.repository is None else f"{project.repository}/blob/{settings.default_branch}/{path}"


def _metadata(
    root: Component, tools: list[Component], request: SbomRequest, project: ProjectIdentity, facts: BuildFacts
) -> Metadata:
    settings = request.settings
    metadata: Final[Metadata] = {
        "timestamp": timestamp(facts),
        "lifecycles": [{"phase": "build"}],
        "tools": {"components": tools},
        "component": root,
    }
    if settings.supplier is not None:
        metadata["manufacturer"] = metadata["supplier"] = settings.supplier
    if "authors" in root:
        metadata["authors"] = root["authors"]
    if "licenses" in root:
        metadata["licenses"] = root["licenses"]
    properties: Final[list[Property]] = [
        {"name": sbom_property(project.property_prefix, "sbom:scope"), "value": _scope(settings)},
        {"name": sbom_property(project.property_prefix, SBOM_FILE), "value": sbom_file_name(request.metadata.name)},
    ]
    if project.repository is not None:
        properties.append({
            "name": sbom_property(project.property_prefix, SBOM_REPOSITORY),
            "value": project.repository,
        })
    metadata["properties"] = properties
    return metadata


def _scope(settings: Settings) -> str:
    declared = (
        "the direct runtime dependencies declared in the wheel's core metadata, which carry no version because the"
        " installer resolves them"
    )
    if directories := " and ".join(sorted({str(PurePosixPath(pattern).parent) for pattern in settings.bundled_wheels})):
        return f"Components are the wheels bundled as data files under {directories} and {declared}."
    return f"Components are {declared}."


__all__ = [
    "describe",
]
