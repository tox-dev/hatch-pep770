from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

from packageurl import PackageURL

from ._components import (
    bundled_wheel_component,
    component_from_metadata,
    file_component,
    mark_bundled,
    vendored_dependencies,
)
from ._graph import artifact_contents
from ._inputs import Artifact
from ._names import archive_sbom_file_name

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
    root: Final[Component] = {
        "type": "application",
        "bom-ref": ref,
        "name": name,
        "version": version,
        "purl": ref,
        "components": [
            distributions.wheel(member) if member.endswith(".whl") else file_component(ref, tree.files[member])
            for member in tree.loose
        ],
    }
    components: Final[list[Component]] = [distributions.component(prefix) for prefix in sorted(tree.metadata)]
    return Artifact(
        root=root,
        components=components,
        dependencies=vendored_dependencies(artifact_contents(root, components)),
        build_scripts=build_scripts,
        version=version,
        sbom_file=archive_sbom_file_name(name),
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
            # a wheel bundled unpacked, named by its directory as a .whl is by its path
            directory = prefix.removesuffix("/")
            mark_bundled(component, directory, self.project.property_prefix, self.bundled_info[directory])
        component["components"] = [
            self.wheel(name) if name.endswith(".whl") else file_component(component["bom-ref"], self.tree.files[name])
            for name in self.tree.owned[prefix]
        ]
        return component

    def wheel(self, name: str) -> Component:
        return bundled_wheel_component(self.tree.bundled[name], self.project.property_prefix, self.bundled_info[name])


def bundled_paths(tree: ArchiveTree) -> list[PurePosixPath]:
    return [PurePosixPath(member.removesuffix("/")) for member in bundled_members(tree.loose, tree.owned)]


def bundled_members(loose: list[str], owned: Mapping[str, list[str]]) -> list[str]:
    # the bundled wheels in the order the components list them, which is the order they are read and a provider is asked
    # about them: the archive's own top-level .whl members, then each wheel bundled unpacked, by its directory ending in
    # "/", followed by the .whl members it holds
    return [
        *(name for name in loose if name.endswith(".whl")),
        *(
            member
            for prefix in sorted(owned)
            for member in ([prefix] if prefix else []) + [name for name in owned[prefix] if name.endswith(".whl")]
        ),
    ]


__all__ = [
    "archive_artifact",
    "bundled_members",
    "bundled_paths",
]
