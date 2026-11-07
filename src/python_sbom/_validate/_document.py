from __future__ import annotations

import json
import re
from collections import Counter
from typing import TYPE_CHECKING, Final, TypeAlias

from python_sbom._formats._spdx import to_spdx
from python_sbom.version import __version__

from ._licenses import license_problems

if TYPE_CHECKING:
    from python_sbom._model._types import Component, Document

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"
# the schema leaves these optional, yet the checks below and the SPDX rendering read them
_REQUIRED: Final[tuple[tuple[str, ...], ...]] = (
    ("metadata", "timestamp"),
    ("metadata", "tools", "components"),
    ("metadata", "component", "bom-ref"),
    ("metadata", "component", "name"),
    ("components",),
    ("dependencies",),
)


def validate(raw: str, allowed_licenses: frozenset[str] | None) -> list[str]:
    """
    Check one CycloneDX SBOM; needs the ``validate`` extra.

    Every document must conform to the CycloneDX 1.6 schema. A document python-sbom wrote must also carry the
    ``urn:uuid`` serial number ``actions/attest`` needs to recognize the format, unique and resolvable ``bom-ref``
    values, a root that depends on exactly the top-level components, an SPDX 2.3 rendering that validates, and, with
    ``allowed_licenses``, licenses the policy allows; documents other tools wrote get the schema check alone.

    :param raw: the JSON text of the document
    :param allowed_licenses: SPDX license ids the shipped components may use, or ``None`` to skip the license policy
    :returns: one message per problem, empty when the document is valid
    :raises MissingExtraError: when the ``validate`` extra is not installed

    """
    from ._schemas import schema_error, spdx_problems  # ruff: ignore[import-outside-top-level] # the optional extra loads on first use

    if error := schema_error(raw):
        return [f"does not conform to the CycloneDX 1.6 schema: {error}"]
    loaded = json.loads(raw)
    # python-sbom names its file in a metadata property, so documents other tools wrote get the schema check alone; the
    # schema already guarantees the shape of what this reads
    if not any(
        prop.get("name", "").endswith(":sbom:file") for prop in loaded.get("metadata", {}).get("properties", [])
    ):
        return []
    if missing := [".".join(path) for path in _REQUIRED if not _has(loaded, path)]:
        return [f"lacks {', '.join(missing)}, which every document python-sbom writes carries"]
    # optional in the CycloneDX spec itself, but actions/attest's format sniffer requires it to recognize the document
    # as CycloneDX at all, and silently rejects anything missing it as an unknown format
    if not re.fullmatch(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        serial := loaded.get("serialNumber", ""),
    ):
        return [f"serialNumber must be a urn:uuid: RFC 4122 UUID, got {serial!r}"]
    # the SPDX rendering of a document whose references are broken only repeats those problems
    problems = _reference_problems(loaded) or spdx_problems(to_spdx(loaded, __version__))
    if allowed_licenses is not None:
        problems.extend(license_problems(loaded["components"], allowed_licenses))
    return problems


def _has(value: _Json, path: tuple[str, ...]) -> bool:
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    return True


def _reference_problems(document: Document) -> list[str]:
    root_ref = document["metadata"]["component"]["bom-ref"]
    tools = document["metadata"]["tools"]["components"]
    every_ref = _bom_refs([document["metadata"]["component"], *document["components"], *tools])
    if duplicates := sorted(ref for ref, count in Counter(every_ref).items() if count > 1):
        return [f"bom-ref values are not unique: {duplicates}"]
    problems: Final[list[str]] = []
    dependencies = {entry["ref"]: set(entry.get("dependsOn", [])) for entry in document["dependencies"]}
    if unknown := (set(dependencies) | set().union(*dependencies.values())) - set(every_ref):
        problems.append(f"dependencies reference bom-refs that do not exist: {sorted(unknown)}")
    if dependencies.get(root_ref) != (component_refs := {component["bom-ref"] for component in document["components"]}):
        problems.append(
            f"root dependsOn {sorted(dependencies.get(root_ref, []))} != components {sorted(component_refs)}"
        )
    tool_refs = {tool["bom-ref"] for tool in tools}
    for formula in document.get("formulation", []):
        for workflow in formula.get("workflows", []):
            if unknown := {reference["ref"] for reference in workflow["resourceReferences"]} - tool_refs:
                problems.append(f"workflow {workflow['uid']} references unknown tools: {sorted(unknown)}")
    return problems


def _bom_refs(components: list[Component]) -> list[str]:
    # iterative, so a deeply nested hostile document cannot exhaust the stack
    found: Final[list[str]] = []
    pending = list(components)
    while pending:
        component = pending.pop()
        found.append(component["bom-ref"])
        pending.extend(component.get("components", []))
    return found


__all__ = [
    "validate",
]
