from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

from packageurl import PackageURL

from ._components import bundled_wheel_component, component_from_metadata, file_component, vendored_dependencies
from ._inputs import Artifact

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._content import BundledWheelInfo
    from ._identity import ProjectIdentity
    from ._inputs import ArchiveTree, BuildScript
    from ._types import Component


def archive_artifact(  # ruff: ignore[too-many-arguments] # keyword-only, each a separate fact the edge read
    name: str,
    tree: ArchiveTree,
    *,
    project: ProjectIdentity,
    bundled_info: Mapping[str, BundledWheelInfo],
    build_scripts: list[BuildScript],
    copyright_line: str | None,
) -> Artifact:
    # the archive's top-level .dist-info names the project; every other .dist-info marks a wheel bundled unpacked into
    # its parent directory and every .whl member a bundled wheel; other files belong to the deepest distribution that
    # holds them, or, at the top level, to the archive
    version: Final[str] = tree.metadata[""].version
    ref: Final[str] = PackageURL(type="generic", name=name, version=version).to_string()
    distributions = _Distributions(tree=tree, project=project, bundled_info=bundled_info)
    components: Final[list[Component]] = [distributions.component(prefix) for prefix in sorted(tree.metadata)]
    return Artifact(
        root={
            "type": "application",
            "bom-ref": ref,
            "name": name,
            "version": version,
            "purl": ref,
            "components": [file_component(ref, tree.files[member]) for member in tree.loose],
        },
        components=components,
        dependencies=vendored_dependencies(components),
        build_scripts=build_scripts,
        version=version,
        sbom_file=f"{name}.cdx.json",
        scope=(
            "Components are the distributions the archive holds, as wheels or unpacked, each with its files; the"
            " archive's own top-level files sit under the root component."
        ),
        workflow=("archive-build", f"build {name} and this SBOM"),
        license_file=next(iter(tree.metadata[""].values("license_files")), None),
        copyright=copyright_line,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class _Distributions:
    tree: ArchiveTree
    project: ProjectIdentity
    bundled_info: Mapping[str, BundledWheelInfo]

    def component(self, prefix: str) -> Component:
        component = component_from_metadata(self.tree.metadata[prefix])
        if prefix:
            # a wheel bundled unpacked: the directory tells copies of one release apart, as the path does for a .whl
            directory = _directory(prefix)
            info = self.bundled_info[str(directory)]
            component["bom-ref"] = f"bundled:{directory}"
            if info.supplier is not None:
                component["supplier"] = info.supplier
            component["properties"] = [
                {"name": f"{self.project.property_prefix}:bundled-wheel", "value": str(directory)},
                *info.properties,
                *component["properties"],
            ]
        component["components"] = [
            self._wheel(name) if name.endswith(".whl") else file_component(component["bom-ref"], self.tree.files[name])
            for name in self.tree.owned[prefix]
        ]
        return component

    def _wheel(self, name: str) -> Component:
        info = self.bundled_info[name]
        return bundled_wheel_component(
            self.tree.bundled[name], self.project.property_prefix, info.properties, info.supplier
        )


def _directory(prefix: str) -> PurePosixPath:
    return PurePosixPath(prefix.rstrip("/"))


def bundled_paths(tree: ArchiveTree) -> list[PurePosixPath]:
    # what a content provider is asked about, in the order the components list them: each wheel bundled unpacked, by its
    # directory, followed by the .whl members it holds
    return [
        path
        for prefix in sorted(tree.metadata)
        for path in (
            *([_directory(prefix)] if prefix else []),
            *(PurePosixPath(name) for name in tree.owned[prefix] if name.endswith(".whl")),
        )
    ]


__all__ = [
    "archive_artifact",
    "bundled_paths",
]
