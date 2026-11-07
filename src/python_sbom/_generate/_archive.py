from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

from packageurl import PackageURL

from python_sbom._collect._archive import member_reader, read_archive
from python_sbom._collect._content import resolve_provider
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._source import copyright_notice
from python_sbom._model._bom import assemble
from python_sbom._model._components import (
    bundled_wheel_component,
    component_from_metadata,
    file_component,
    vendored_dependencies,
)
from python_sbom._model._content import ProviderContext
from python_sbom._model._document import checked_contributions
from python_sbom._model._identity import project_identity
from python_sbom._model._inputs import Artifact, BuildScript

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._identity import ProjectIdentity
    from python_sbom._model._inputs import ArchiveTree, BuildFacts
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
    settings = settings_from_pyproject(root)
    content, provider_scripts = resolve_provider(provider, settings, root)
    tree = read_archive(archive)
    project = project_identity(tree.metadata[""], settings)
    reader = _Reader(
        tree=tree,
        project=project,
        content=content,
        context=ProviderContext(root=root, settings=settings, identity=project, read=member_reader(archive)),
    )
    version: Final[str] = tree.metadata[""].version
    ref: Final[str] = PackageURL(type="generic", name=archive.name, version=version).to_string()
    components: Final[list[Component]] = [reader.distribution(prefix) for prefix in sorted(tree.metadata)]
    license_files: Final[list[str]] = tree.metadata[""].values("license_files")
    artifact = Artifact(
        root={
            "type": "application",
            "bom-ref": ref,
            "name": archive.name,
            "version": version,
            "purl": ref,
            "components": [file_component(ref, tree.files[name]) for name in tree.loose],
        },
        components=components,
        dependencies=vendored_dependencies(components),
        build_scripts=[
            BuildScript(path=path, sha256=hashlib.sha256((root / str(path)).read_bytes()).hexdigest())
            for path in dict.fromkeys([*build_scripts, *provider_scripts])
        ],
        version=version,
        sbom_file=f"{archive.name}.cdx.json",
        scope=(
            "Components are the distributions the archive holds, as wheels or unpacked, each with its files; the"
            " archive's own top-level files sit under the root component."
        ),
        workflow=("archive-build", f"build {archive.name} and this SBOM"),
        license_file=next(iter(license_files), None),
        copyright=copyright_notice(root, license_files),
    )
    contributions = checked_contributions(content.contributions(reader.context), content)
    return assemble(artifact, project, settings, facts, contributions)


@dataclass(frozen=True, slots=True, kw_only=True)
class _Reader:
    tree: ArchiveTree
    project: ProjectIdentity
    content: ContentProvider
    context: ProviderContext

    def distribution(self, prefix: str) -> Component:
        component = component_from_metadata(self.tree.metadata[prefix])
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
            self.wheel(name) if name.endswith(".whl") else file_component(component["bom-ref"], self.tree.files[name])
            for name in self.tree.owned[prefix]
        ]
        return component

    def wheel(self, name: str) -> Component:
        info = self.content.bundled_wheel(self.context, PurePosixPath(name))
        return bundled_wheel_component(
            self.tree.bundled[name], self.project.property_prefix, info.properties, info.supplier
        )


__all__ = [
    "describe_archive",
]
