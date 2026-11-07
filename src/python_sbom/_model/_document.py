from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from ._content import ContentProvider
    from ._inputs import BuildFacts, Contributions
    from ._types import Body, Component, Document, Formula, Property


def with_header(body: Body, namespace: uuid.UUID) -> Document:
    # a provider contributes refs of its own, so the document is checked before it is written rather than by validate
    components: Final[list[Component]] = [
        *walk_components([
            body["metadata"]["component"],
            *body["components"],
            *body["metadata"]["tools"]["components"],
        ])
    ]
    refs: Final[Counter[str]] = Counter(component["bom-ref"] for component in components)
    # formulas and workflows share the bom-ref namespace, so a component cannot take theirs
    refs.update(
        ref
        for formula in body.get("formulation", [])
        for ref in (formula["bom-ref"], *(workflow["bom-ref"] for workflow in formula["workflows"]))
    )
    if repeated := sorted(ref for ref, count in refs.items() if count > 1):
        msg = f"bom-ref values repeat: {', '.join(repeated)}"
        raise SbomError(msg)
    # one entry per component, as validation requires, so a provider adds to a component's dependencies, not a second
    # entry for it
    entries: Final[Counter[str]] = Counter(entry["ref"] for entry in body["dependencies"])
    if repeated := sorted(ref for ref, count in entries.items() if count > 1):
        msg = f"dependencies list more than one entry for: {', '.join(repeated)}"
        raise SbomError(msg)
    known: Final[set[str]] = {component["bom-ref"] for component in components}
    named = {ref for entry in body["dependencies"] for ref in (entry["ref"], *entry.get("dependsOn", []))}
    if unknown := sorted(named - known):
        msg = f"dependencies name bom-refs no component has: {', '.join(unknown)}"
        raise SbomError(msg)
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }


def walk_components(components: Iterable[Component]) -> Iterator[Component]:
    # depth first, each component before the ones it nests, in document order; iterative, so a deeply nested document
    # cannot exhaust the stack
    pending: Final[list[Component]] = list(reversed(list(components)))
    while pending:
        component = pending.pop()
        yield component
        pending.extend(reversed(component.get("components", [])))


def checked_contributions(contributions: Contributions, provider: ContentProvider) -> Contributions:
    # what a provider adds is checked for the fields everything else here reads, so a mistake names the provider rather
    # than surfacing as a KeyError deep in the build
    for component in walk_components([*contributions.components, *contributions.tools]):
        if missing := [key for key in ("type", "bom-ref", "name") if key not in component]:
            name = type(provider).__qualname__
            msg = f"content provider {name} added a component without {', '.join(missing)}: {component!r:.200}"
            raise SbomError(msg)
    return contributions


def contributed_properties(properties: list[Property], prefix: str) -> list[Property]:
    if claimed := sorted(prop["name"] for prop in properties if prop["name"].startswith(f"{prefix}:")):
        msg = f"contributed root properties {', '.join(claimed)} use the {prefix}: prefix python-sbom writes"
        raise SbomError(msg)
    return properties


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


def timestamp(facts: BuildFacts) -> str:
    return datetime.fromtimestamp(facts.epoch, tz=UTC).isoformat()


__all__ = [
    "checked_contributions",
    "contributed_properties",
    "formulation",
    "timestamp",
    "walk_components",
    "with_header",
]
