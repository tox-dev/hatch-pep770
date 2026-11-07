from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from packaging.requirements import Requirement

from ._components import bundled_wheel_component, component_from_metadata, script_tool, vendored_dependencies
from ._document import contributed_properties, formulation, timestamp, with_header
from ._identity import project_identity
from ._inputs import Artifact
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
    metadata, settings = request.metadata, request.settings
    project = project_identity(metadata, settings)
    bundled = [
        bundled_wheel_component(
            wheel,
            project.property_prefix,
            bundled_info[wheel.path].properties,
            bundled_info[wheel.path].supplier,
        )
        for wheel in source.bundled
    ]
    root = component_from_metadata(metadata)
    root["type"] = "application"
    name, version = metadata.name, metadata.version
    root["externalReferences"] = [
        *root["externalReferences"],
        {"type": "distribution", "url": pypi_url(name, version)},
        {"type": "attestation", "url": f"https://pypi.org/integrity/{name}/{version}/{request.wheel_name}/provenance"},
    ]
    artifact = Artifact(
        root=root,
        components=[
            *bundled,
            # hatchling repeats a Requires-Dist when a hook re-adds a dependency, and each bom-ref must be unique
            *(
                _declared_dependency(text, requirement, project.property_prefix)
                for text in dict.fromkeys(metadata.values("requires_dist"))
                if applies_without_extras(requirement := Requirement(text))
            ),
        ],
        dependencies=vendored_dependencies(bundled),
        build_scripts=source.build_scripts,
        version=version,
        sbom_file=sbom_file_name(name),
        scope=_scope(settings),
        workflow=("wheel-build", "build the wheel and this SBOM"),
        license_file=next(iter(metadata.values("license_files")), None),
        copyright=source.copyright,
    )
    return assemble(artifact, project, settings, facts, contributions)


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


def _scope(settings: Settings) -> str:
    declared = (
        "the direct runtime dependencies declared in the wheel's core metadata, which carry no version because the"
        " installer resolves them"
    )
    if directories := " and ".join(sorted({str(PurePosixPath(pattern).parent) for pattern in settings.bundled_wheels})):
        return f"Components are the wheels bundled as data files under {directories} and {declared}."
    return f"Components are {declared}."


def assemble(
    artifact: Artifact, project: ProjectIdentity, settings: Settings, facts: BuildFacts, contributions: Contributions
) -> Document:
    # what every artifact of the project carries alike: who supplies it, where its source lives and at which revision,
    # the tools that built it and what the project contributes
    root = _provenance(artifact, project, settings, facts, contributions)
    components: Final[list[Component]] = [*artifact.components, *contributions.components]
    environment, tool_dependencies = tool_components(facts)
    tools: Final[list[Component]] = [
        *(
            script_tool(script.path, script.sha256, artifact.version, _file_link(project, settings, script.path))
            for script in artifact.build_scripts
        ),
        *environment,
        *contributions.tools,
    ]
    uid, name = artifact.workflow
    return with_header(
        {
            "metadata": _metadata(tools, artifact, project, settings, facts),
            "components": components,
            "dependencies": [
                {"ref": root["bom-ref"], "dependsOn": [component["bom-ref"] for component in components]},
                *artifact.dependencies,
                *tool_dependencies,
                *contributions.dependencies,
            ],
            # what the artifact needs at run time beyond what it ships, an interpreter and the dependencies an installer
            # resolves, is not listed
            "compositions": [{"aggregate": "incomplete", "dependencies": [root["bom-ref"]]}],
            "formulation": [formulation(uid, name, tools, root["bom-ref"], facts)],
        },
        project.serial_namespace,
    )


def _provenance(
    artifact: Artifact, project: ProjectIdentity, settings: Settings, facts: BuildFacts, contributions: Contributions
) -> Component:
    root = artifact.root
    if settings.supplier is not None:
        root["supplier"] = settings.supplier
    if artifact.copyright is not None:
        root["copyright"] = artifact.copyright
    references: Final[list[ExternalReference]] = [*root.get("externalReferences", [])]
    if project.repository and urlsplit(project.repository).netloc == "github.com":
        references.extend([
            {"type": "security-contact", "url": f"{project.repository}/security/policy"},
            {"type": "advisories", "url": f"{project.repository}/security/advisories"},
        ])
    if artifact.license_file is not None and (
        link := _file_link(project, settings, PurePosixPath(artifact.license_file))
    ):
        references.append({"type": "license", "url": link})
    properties: Final[list[Property]] = [
        *root.get("properties", []),
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


def _file_link(project: ProjectIdentity, settings: Settings, path: PurePosixPath) -> str | None:
    return None if project.repository is None else f"{project.repository}/blob/{settings.default_branch}/{path}"


def _metadata(
    tools: list[Component],
    artifact: Artifact,
    project: ProjectIdentity,
    settings: Settings,
    facts: BuildFacts,
) -> Metadata:
    metadata: Final[Metadata] = {
        "timestamp": timestamp(facts),
        "lifecycles": [{"phase": "build"}],
        "tools": {"components": tools},
        "component": (root := artifact.root),
    }
    if settings.supplier is not None:
        metadata["manufacturer"] = metadata["supplier"] = settings.supplier
    if "authors" in root:
        metadata["authors"] = root["authors"]
    if "licenses" in root:
        metadata["licenses"] = root["licenses"]
    properties: Final[list[Property]] = [
        {"name": sbom_property(project.property_prefix, "sbom:scope"), "value": artifact.scope},
        # names the document's file, which marks it as one python-sbom built, so validation checks it in full
        {"name": sbom_property(project.property_prefix, SBOM_FILE), "value": artifact.sbom_file},
    ]
    if project.repository is not None:
        properties.append({
            "name": sbom_property(project.property_prefix, SBOM_REPOSITORY),
            "value": project.repository,
        })
    metadata["properties"] = properties
    return metadata


__all__ = [
    "assemble",
    "describe",
]
