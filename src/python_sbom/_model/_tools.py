"""Describe the build tools: the interpreter, the installed distributions and the build scripts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from packageurl import PackageURL

from ._components import component_from_metadata, file_component
from ._names import purl, tool_ref

if TYPE_CHECKING:
    from pathlib import PurePosixPath

    from ._inputs import BuildFacts
    from ._types import Component, Dependency


def tool_components(facts: BuildFacts) -> tuple[list[Component], list[Dependency]]:
    interpreter = facts.interpreter
    package = PackageURL(type="generic", name=interpreter.name, version=interpreter.version).to_string()
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
        distribution.name: tool_ref(purl(distribution.name, distribution.metadata.version))
        for distribution in facts.distributions
    }
    dependencies: Final[list[Dependency]] = []
    for distribution in sorted(facts.distributions, key=lambda entry: entry.name):
        component = component_from_metadata(distribution.metadata)
        component["bom-ref"] = refs[distribution.name]
        if distribution.files:
            component["components"] = [file_component(component["bom-ref"], row) for row in distribution.files]
        tools.append(component)
        dependencies.append({
            "ref": component["bom-ref"],
            "dependsOn": sorted(refs[name] for name in distribution.depends_on),
        })
    return tools, dependencies


def script_tool(path: PurePosixPath, sha256: str, version: str, link: str | None) -> Component:
    tool: Final[Component] = {
        "type": "application",
        "bom-ref": tool_ref(str(path)),
        "name": path.name,
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": sha256}],
    }
    if link is not None:
        tool["externalReferences"] = [{"type": "vcs", "url": link}]
    return tool


__all__ = [
    "script_tool",
    "tool_components",
]
