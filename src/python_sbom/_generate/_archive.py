from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

from packageurl import PackageURL

from python_sbom._collect._content import load_content_provider, provider_script
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._source import read_bundled_wheel
from python_sbom._errors import WheelError
from python_sbom._model._components import (
    bundled_wheel_component,
    component_from_metadata,
    file_component_from_bytes,
    script_tool,
    vendored_dependencies,
)
from python_sbom._model._content import ProviderContext
from python_sbom._model._document import contributed_properties, formulation, timestamp, with_header
from python_sbom._model._identity import project_identity
from python_sbom._model._metadata import parse_metadata
from python_sbom._model._names import SBOM_FILE, sbom_property
from python_sbom._model._tools import tool_components
from python_sbom._model._types import Dependency
from python_sbom._wheel._archive import open_archive

if TYPE_CHECKING:
    from collections.abc import Sequence

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._identity import ProjectIdentity
    from python_sbom._model._inputs import BuildFacts, Settings
    from python_sbom._model._metadata import CoreMetadata
    from python_sbom._model._types import Component, Document, Metadata


def describe_archive(
    root: Path,
    archive: Path,
    *,
    facts: BuildFacts,
    content: ContentProvider | None = None,
    build_scripts: Sequence[PurePosixPath] = (),
) -> Document:
    # the archive's top-level .dist-info names the project; every other .dist-info marks a wheel bundled unpacked into
    # its parent directory and every .whl member a bundled wheel; other files belong to the deepest distribution that
    # holds them, or, at the top level, to the archive
    settings = settings_from_pyproject(root, {})
    content = content or load_content_provider(settings.content_provider, root)
    with tempfile.TemporaryDirectory() as directory:
        held = _read_archive(root, archive, Path(directory), settings, content)
        contributions = content.contributions(held.reader.context)
    held.root["properties"] = list(contributed_properties(contributions.root_properties, held.project.property_prefix))
    if facts.revision is not None:
        held.root["properties"].append({
            "name": f"{held.project.property_prefix}:vcs-commit",
            "value": facts.revision.commit,
        })
    components: Final[list[Component]] = [*held.components, *contributions.components]
    tools: Final[list[Component]] = [
        *(
            script_tool(
                path,
                hashlib.sha256((root / str(path)).read_bytes()).hexdigest(),
                held.version,
                None
                if held.project.repository is None
                else f"{held.project.repository}/blob/{settings.default_branch}/{path}",
            )
            for path in [*build_scripts, *filter(None, [provider_script(content, root)])]
        ),
        *(environment := tool_components(facts))[0],
        *contributions.tools,
    ]
    metadata: Final[Metadata] = {
        "timestamp": timestamp(facts),
        "lifecycles": [{"phase": "build"}],
        "tools": {"components": tools},
        "component": held.root,
        # names the document's file, which marks it as one python-sbom built, so validation checks it in full
        "properties": [
            {"name": sbom_property(held.project.property_prefix, SBOM_FILE), "value": f"{archive.name}.cdx.json"}
        ],
    }
    if settings.supplier is not None:
        held.root["supplier"] = metadata["manufacturer"] = metadata["supplier"] = settings.supplier
    return with_header(
        {
            "metadata": metadata,
            "components": components,
            "dependencies": [
                Dependency(ref=held.root["bom-ref"], dependsOn=[component["bom-ref"] for component in components]),
                *vendored_dependencies(components),
                *environment[1],
                *contributions.dependencies,
            ],
            "formulation": [
                formulation("archive-build", f"build {archive.name} and this SBOM", tools, held.root["bom-ref"], facts)
            ],
        },
        held.project.serial_namespace,
    )


def _read_archive(root: Path, archive: Path, unpacked: Path, settings: Settings, content: ContentProvider) -> _Held:
    # unpacked, so a content provider reads the archive's files the way it reads the project's
    with open_archive(archive, archive.name) as handle:
        members = sorted(
            name for name in handle.namelist() if not name.endswith("/") and name != f"{archive.name}.cdx.json"
        )
        handle.extractall(unpacked)
    # each distribution by the directory that holds its .dist-info, the project's own at the top level
    metadata = {
        f"{name.rsplit('/', 2)[0]}/" if name.count("/") > 1 else "": parse_metadata(
            (unpacked / name).read_text(encoding="utf-8")
        )
        for name in members
        if name.endswith(".dist-info/METADATA")
    }
    if (top := sum(name.count("/") == 1 and name.endswith(".dist-info/METADATA") for name in members)) != 1:
        msg = f"{archive.name} holds {top} top-level .dist-info/METADATA, not the one naming the project"
        raise WheelError(msg)
    owned: Final[dict[str, list[str]]] = {prefix: [] for prefix in metadata}
    loose: Final[list[str]] = []
    for name in members:
        # the deepest distribution directory that holds the file; the project's own holds every other subdirectory
        if owner := max((prefix for prefix in metadata if prefix and name.startswith(prefix)), key=len, default=""):
            owned[owner].append(name)
        elif "/" in name:
            owned[""].append(name)
        else:
            loose.append(name)
    project = project_identity(metadata[""], settings)
    reader = _Reader(
        unpacked=unpacked,
        project=project,
        settings=settings,
        content=content,
        context=ProviderContext(root=root, settings=settings, identity=project, artifact=unpacked),
    )
    version = metadata[""].version
    ref = PackageURL(type="generic", name=archive.name, version=version).to_string()
    return _Held(
        reader=reader,
        project=reader.project,
        version=version,
        root={
            "type": "application",
            "bom-ref": ref,
            "name": archive.name,
            "version": version,
            "purl": ref,
            "components": [reader.file(ref, name) for name in loose],
        },
        components=[reader.distribution(prefix, metadata[prefix], owned[prefix]) for prefix in sorted(metadata)],
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class _Reader:
    unpacked: Path
    project: ProjectIdentity
    settings: Settings
    content: ContentProvider
    context: ProviderContext

    def distribution(self, prefix: str, metadata: CoreMetadata, names: list[str]) -> Component:
        component = component_from_metadata(metadata)
        if prefix:
            # a wheel bundled unpacked: the directory tells copies of one release apart, as the path does for a .whl
            directory = PurePosixPath(prefix.rstrip("/"))
            info = self.content.bundled_wheel(self.context, directory)
            component["bom-ref"] = f"bundled:{directory}"
            if info.supplier is not None:
                component["supplier"] = info.supplier
            component["properties"] = [
                {"name": f"{self.project.property_prefix}:bundled-wheel", "value": str(directory)},
                *info.properties,
                *component["properties"],
            ]
        component["components"] = [
            self.wheel(name) if name.endswith(".whl") else self.file(component["bom-ref"], name) for name in names
        ]
        return component

    def wheel(self, name: str) -> Component:
        info = self.content.bundled_wheel(self.context, PurePosixPath(name))
        return bundled_wheel_component(
            read_bundled_wheel((self.unpacked / name).read_bytes(), name),
            self.project.property_prefix,
            info.properties,
            info.supplier,
        )

    def file(self, parent: str, name: str) -> Component:
        return file_component_from_bytes(parent, name, (self.unpacked / name).read_bytes())


@dataclass(frozen=True, slots=True, kw_only=True)
class _Held:
    reader: _Reader
    project: ProjectIdentity
    version: str
    root: Component
    components: list[Component]


__all__ = [
    "describe_archive",
]
