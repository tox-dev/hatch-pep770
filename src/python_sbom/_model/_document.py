from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from python_sbom._errors import SbomError

if TYPE_CHECKING:
    from ._inputs import BuildFacts
    from ._types import Body, Component, Document, Formula, Property


def with_header(body: Body, namespace: uuid.UUID) -> Document:
    # a provider contributes refs of its own, so the document is checked before it is written rather than by validate
    refs: Final[Counter[str]] = Counter()
    pending: Final[list[Component]] = [
        body["metadata"]["component"],
        *body["components"],
        *body["metadata"]["tools"]["components"],
    ]
    while pending:
        component = pending.pop()
        refs[component["bom-ref"]] += 1
        pending.extend(component.get("components", []))
    if repeated := sorted(ref for ref, count in refs.items() if count > 1):
        msg = f"bom-ref values repeat: {', '.join(repeated)}"
        raise SbomError(msg)
    named = {ref for entry in body["dependencies"] for ref in (entry["ref"], *entry.get("dependsOn", []))}
    if unknown := sorted(named - refs.keys()):
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
    "contributed_properties",
    "formulation",
    "timestamp",
    "with_header",
]
