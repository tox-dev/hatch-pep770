from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

from packaging.requirements import Requirement

from ._components import bundled_wheel_component, component_from_metadata, vendored_dependencies
from ._inputs import Artifact
from ._markers import applies_without_extras
from ._names import purl, pypi_url, sbom_file_name, sbom_property

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._content import BundledWheelInfo
    from ._identity import ProjectIdentity
    from ._inputs import Settings, WheelTree
    from ._types import Component


def wheel_artifact(
    tree: WheelTree, *, project: ProjectIdentity, settings: Settings, bundled_info: Mapping[str, BundledWheelInfo]
) -> Artifact:
    metadata = tree.metadata
    bundled = [
        bundled_wheel_component(wheel, project.property_prefix, bundled_info[wheel.path]) for wheel in tree.bundled
    ]
    root = component_from_metadata(metadata)
    root["type"] = "application"
    name, version = metadata.name, metadata.version
    root["externalReferences"] = [
        *root["externalReferences"],
        {"type": "distribution", "url": pypi_url(name, version)},
        {"type": "attestation", "url": f"https://pypi.org/integrity/{name}/{version}/{tree.name}/provenance"},
    ]
    return Artifact(
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
        build_scripts=tree.build_scripts,
        version=version,
        sbom_file=sbom_file_name(name),
        scope=_scope(settings),
        workflow=("wheel-build", "build the wheel and this SBOM"),
        license_file=next(iter(metadata.values("license_files")), None),
        copyright=tree.copyright,
    )


def _declared_dependency(text: str, requirement: Requirement, property_prefix: str) -> Component:
    component: Final[Component] = {
        "type": "library",
        # the same distribution can be declared more than once with different markers, so the purl is not unique
        "bom-ref": f"requires-dist:{text}",
        "name": requirement.name,
        "purl": purl(requirement.name),
        "externalReferences": [{"type": "distribution", "url": pypi_url(requirement.name)}],
        "properties": [{"name": sbom_property(property_prefix, "requires-dist"), "value": text}],
    }
    if requirement.marker is not None:
        component["properties"].append({
            "name": sbom_property(property_prefix, "environment-marker"),
            "value": str(requirement.marker),
        })
    return component


def _scope(settings: Settings) -> str:
    declared = (
        "the direct runtime dependencies declared in the wheel's core metadata, which carry no version because the"
        " installer resolves them"
    )
    if directories := " and ".join(sorted({str(PurePosixPath(pattern).parent) for pattern in settings.bundled_wheels})):
        return f"Components are the wheels bundled as data files under {directories} and {declared}."
    return f"Components are {declared}."


__all__ = [
    "wheel_artifact",
]
