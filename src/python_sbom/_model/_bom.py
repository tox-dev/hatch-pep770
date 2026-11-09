from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from python_sbom import SbomError

from ._graph import reference_problems, walk_components
from ._names import SBOM_FILE, SBOM_REPOSITORY, sbom_property
from ._tools import script_tool, tool_components

if TYPE_CHECKING:
    from ._content import ContentProvider, Contributions
    from ._identity import ProjectIdentity
    from ._inputs import Artifact, BuildFacts, Settings
    from ._types import Body, Component, Document, ExternalReference, Formula, Metadata, Property


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


def contributed_properties(properties: list[Property], prefix: str) -> list[Property]:
    if claimed := sorted(prop["name"] for prop in properties if prop["name"].startswith(f"{prefix}:")):
        msg = f"contributed root properties {', '.join(claimed)} use the {prefix}: prefix python-sbom writes"
        raise SbomError(msg)
    return properties


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
        "timestamp": datetime.fromtimestamp(facts.epoch, tz=UTC).isoformat(),
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


def formulation(uid: str, name: str, tools: list[Component], output_ref: str, facts: BuildFacts) -> Formula:
    formula: Formula = {
        "bom-ref": f"formula:{uid}",
        "workflows": [
            {
                "bom-ref": f"workflow:{uid}",
                "uid": uid,
                "name": name,
                "taskTypes": ["build"],
                "resourceReferences": [{"ref": tool["bom-ref"]} for tool in tools],
                "outputs": [{"type": "artifact", "resource": {"ref": output_ref}}],
            }
        ],
    }
    if facts.epoch_from_environment:
        formula["workflows"][0]["inputs"] = [
            {"environmentVars": [{"name": "SOURCE_DATE_EPOCH", "value": str(facts.epoch)}]}
        ]
    return formula


def check_refs(body: Body) -> None:
    # a provider contributes refs of its own, so the document is checked before it is written rather than by validate
    components: Final[list[Component]] = [
        *walk_components([
            body["metadata"]["component"],
            *body["components"],
            *body["metadata"]["tools"]["components"],
        ])
    ]
    # formulas and workflows share the bom-ref namespace, so a component cannot take theirs
    formulas: Final[list[str]] = [
        ref
        for formula in body.get("formulation", [])
        for ref in (formula["bom-ref"], *(workflow["bom-ref"] for workflow in formula["workflows"]))
    ]
    if problems := reference_problems(
        [*(component["bom-ref"] for component in components), *formulas], body["dependencies"]
    ):
        raise SbomError(problems[0])


def with_header(body: Body, serial_namespace: uuid.UUID) -> Document:
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(serial_namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }


def checked_contributions(contributions: Contributions, provider: ContentProvider) -> Contributions:
    # what a provider adds is checked for the fields everything else here reads, so a mistake names the provider rather
    # than surfacing as a KeyError deep in the build
    for component in walk_components([*contributions.components, *contributions.tools]):
        if missing := [key for key in ("type", "bom-ref", "name") if key not in component]:
            name = type(provider).__qualname__
            msg = f"content provider {name} added a component without {', '.join(missing)}: {component!r:.200}"
            raise SbomError(msg)
    return contributions


__all__ = [
    "assemble",
    "check_refs",
    "checked_contributions",
    "contributed_properties",
    "formulation",
    "with_header",
]
