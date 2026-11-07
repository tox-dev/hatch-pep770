from __future__ import annotations

from typing import TYPE_CHECKING, Final

from packaging.utils import canonicalize_name

from ._components import component_from_metadata, file_component, purl, tool_ref

if TYPE_CHECKING:
    from ._inputs import BuildFacts
    from ._types import Component, Dependency


def tool_components(facts: BuildFacts) -> tuple[list[Component], list[Dependency]]:
    """
    Describe the build environment as build tools: the interpreter first, then every distribution by name.

    :param facts: the collected build facts
    :returns: the tool components and the dependency entries between the distributions

    """
    interpreter = facts.interpreter
    package = f"pkg:generic/{interpreter.name}@{interpreter.version}"
    tools: Final[list[Component]] = [
        {
            "type": "platform",
            "bom-ref": tool_ref(package),
            "name": interpreter.name,
            "version": interpreter.version,
            "purl": package,
            "properties": [{"name": "python:implementation", "value": interpreter.implementation}],
        }
    ]
    refs: Final[dict[str, str]] = {
        canonicalize_name(distribution.metadata["Name"]): tool_ref(
            purl(distribution.metadata["Name"], distribution.metadata["Version"])
        )
        for distribution in facts.distributions
    }
    dependencies: Final[list[Dependency]] = []
    for distribution in sorted(facts.distributions, key=lambda entry: canonicalize_name(entry.metadata["Name"])):
        component = component_from_metadata(distribution.metadata)
        component["bom-ref"] = refs[canonicalize_name(distribution.metadata["Name"])]
        if distribution.files:
            component["components"] = [file_component(component["bom-ref"], row) for row in distribution.files]
        tools.append(component)
        dependencies.append({
            "ref": component["bom-ref"],
            "dependsOn": sorted(refs[name] for name in distribution.depends_on),
        })
    return tools, dependencies


__all__ = [
    "tool_components",
]
