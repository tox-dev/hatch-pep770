from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError

from ._graph import reference_problems, walk_components

if TYPE_CHECKING:
    from ._content import ContentProvider, Contributions
    from ._inputs import BuildFacts
    from ._types import Body, Component, Document, Formula, Property


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
    "check_refs",
    "checked_contributions",
    "contributed_properties",
    "formulation",
    "timestamp",
    "with_header",
]
