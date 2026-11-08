from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from ._components import script_tool
from ._document import check_refs, contributed_properties, formulation, timestamp, with_header
from ._names import SBOM_FILE, SBOM_REPOSITORY, sbom_property
from ._tools import tool_components

if TYPE_CHECKING:
    from ._content import Contributions
    from ._identity import ProjectIdentity
    from ._inputs import Artifact, BuildFacts, Settings
    from ._types import Body, Component, Document, ExternalReference, Metadata, Property


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
            script_tool(script.path, script.sha256, artifact.version, _file_link(project, settings, facts, script.path))
            for script in artifact.build_scripts
        ),
        *environment,
        *contributions.tools,
    ]
    uid, name = artifact.workflow
    body: Final[Body] = {
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
    }
    check_refs(body)
    return with_header(body, project.serial_namespace)


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
        link := _file_link(project, settings, facts, PurePosixPath(artifact.license_file))
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
        properties.append({"name": sbom_property(project.property_prefix, "vcs-commit"), "value": revision.commit})
        if revision.dirty:
            properties.append({"name": sbom_property(project.property_prefix, "vcs-dirty"), "value": "true"})
    root["externalReferences"] = references
    root["properties"] = properties
    return root


def _file_link(project: ProjectIdentity, settings: Settings, facts: BuildFacts, path: PurePosixPath) -> str | None:
    if project.repository is None:
        return None
    # the commit of a clean checkout holds the file as it was built; with no commit, or uncommitted changes, the default
    # branch is where the file most likely still lives
    revision = facts.revision
    tree = settings.default_branch if revision is None or revision.dirty else revision.commit
    return f"{project.repository}/blob/{tree}/{path}"


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
]
