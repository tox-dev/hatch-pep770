from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

from packageurl import PackageURL

from python_sbom._collect._content import resolve_provider
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._source import copyright_notice, read_bundled_wheels
from python_sbom._errors import WheelError
from python_sbom._model._bom import assemble
from python_sbom._model._components import (
    bundled_wheel_component,
    component_from_metadata,
    file_component_from_bytes,
    vendored_dependencies,
)
from python_sbom._model._content import ProviderContext
from python_sbom._model._document import checked_contributions
from python_sbom._model._identity import project_identity
from python_sbom._model._inputs import Artifact, BuildScript
from python_sbom._model._metadata import parse_metadata
from python_sbom._wheel._archive import open_archive

if TYPE_CHECKING:
    from collections.abc import Sequence

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._identity import ProjectIdentity
    from python_sbom._model._inputs import BuildFacts, BundledWheel, Settings
    from python_sbom._model._metadata import CoreMetadata
    from python_sbom._model._types import Component, Document


def describe_archive(
    root: Path,
    archive: Path,
    *,
    facts: BuildFacts,
    provider: ContentProvider | str | None,
    build_scripts: Sequence[PurePosixPath],
) -> Document:
    # the archive's top-level .dist-info names the project; every other .dist-info marks a wheel bundled unpacked into
    # its parent directory and every .whl member a bundled wheel; other files belong to the deepest distribution that
    # holds them, or, at the top level, to the archive
    settings = settings_from_pyproject(root, {})
    content, provider_scripts = resolve_provider(provider, settings, root)
    with tempfile.TemporaryDirectory() as directory:
        held = _read_archive(root, archive, Path(directory), settings, content)
        contributions = checked_contributions(content.contributions(held.reader.context), content)
    license_files: Final[list[str]] = held.metadata.values("license_files")
    artifact = Artifact(
        root=held.root,
        components=held.components,
        dependencies=vendored_dependencies(held.components),
        build_scripts=[
            BuildScript(path=path, sha256=hashlib.sha256((root / str(path)).read_bytes()).hexdigest())
            for path in dict.fromkeys([*build_scripts, *provider_scripts])
        ],
        version=held.metadata.version,
        sbom_file=f"{archive.name}.cdx.json",
        scope=(
            "Components are the distributions the archive holds, as wheels or unpacked, each with its files; the"
            " archive's own top-level files sit under the root component."
        ),
        workflow=("archive-build", f"build {archive.name} and this SBOM"),
        license_file=next(iter(license_files), None),
        copyright=copyright_notice(root, license_files),
    )
    return assemble(artifact, held.reader.project, settings, facts, contributions)


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
    wheels: Final[list[str]] = [name for prefix in sorted(metadata) for name in owned[prefix] if name.endswith(".whl")]
    reader = _Reader(
        unpacked=unpacked,
        bundled=dict(zip(wheels, read_bundled_wheels(unpacked, wheels), strict=True)),
        project=project,
        settings=settings,
        content=content,
        context=ProviderContext(root=root, settings=settings, identity=project, artifact=unpacked),
    )
    version = metadata[""].version
    ref = PackageURL(type="generic", name=archive.name, version=version).to_string()
    return _Held(
        reader=reader,
        metadata=metadata[""],
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
    # read ahead, in the order the components list them
    bundled: dict[str, BundledWheel]
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
            self.bundled[name],
            self.project.property_prefix,
            info.properties,
            info.supplier,
        )

    def file(self, parent: str, name: str) -> Component:
        return file_component_from_bytes(parent, name, (self.unpacked / name).read_bytes())


@dataclass(frozen=True, slots=True, kw_only=True)
class _Held:
    reader: _Reader
    # the project's own, from the archive's top-level .dist-info
    metadata: CoreMetadata
    root: Component
    components: list[Component]


__all__ = [
    "describe_archive",
]
