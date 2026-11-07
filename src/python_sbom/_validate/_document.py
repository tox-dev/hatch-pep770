from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import TYPE_CHECKING, Final, TypeAlias

from python_sbom._errors import MissingExtraError
from python_sbom._formats._spdx import render_spdx
from python_sbom._model._names import SBOM_FILE
from python_sbom.version import __version__

if TYPE_CHECKING:
    from typing import TypeIs  # new in 3.13; annotations here are never evaluated

    from python_sbom._model._types import Component, Document

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"
# the schema leaves these optional, yet every document python-sbom writes carries them and the checks below read them
_REQUIRED: Final[tuple[tuple[str, ...], ...]] = (
    ("metadata", "timestamp"),
    ("metadata", "tools", "components"),
    ("metadata", "component", "bom-ref"),
    ("metadata", "component", "name"),
    ("components",),
    ("dependencies",),
)
_SERIAL: Final[re.Pattern[str]] = re.compile(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# the archive reader stops at the same size
_MAX_CHARACTERS: Final[int] = 16 * 1024 * 1024
# every check takes time in proportion to the count, so the cap bounds the work an untrusted document can ask for, far
# above the few thousand components a wheel with its build tools' files lists
MAX_COMPONENTS: Final[int] = 100_000
# an exception's message can quote the hostile value that caused it
_MAX_TEXT: Final[int] = 200
# the schema validator recurses once per level and crashes the process past a few thousand levels on a small thread
# stack; the SBOMs python-sbom and other tools write nest about a dozen levels deep
_MAX_DEPTH: Final[int] = 128


def validate_document(
    raw: str, allowed_licenses: frozenset[str] | None, max_components: int = MAX_COMPONENTS
) -> list[str]:
    if len(raw) > _MAX_CHARACTERS:
        return [f"is {len(raw)} characters long, over the {_MAX_CHARACTERS} character limit"]
    # one document's problem never stops the others from being checked, so whatever the checks raise is reported
    try:
        return _problems(raw, allowed_licenses, max_components)
    except MissingExtraError:
        raise
    except json.JSONDecodeError as error:
        return [f"is not JSON: {error}"]
    except RecursionError:
        # the JSON parser recurses once per level, how deep it gets depends on the Python version
        return [f"nests more than {_MAX_DEPTH} levels deep, too deep to check"]
    except Exception as error:  # ruff: ignore[blind-except] # a hostile document may trip any check, see above
        return [f"could not be checked, {type(error).__name__}: {str(error)[:_MAX_TEXT]}"]


def _problems(raw: str, allowed_licenses: frozenset[str] | None, max_components: int) -> list[str]:
    # every document must conform to the CycloneDX 1.6 schema; one python-sbom wrote must also carry the urn:uuid serial
    # actions/attest needs, resolvable and unique bom-refs and a valid SPDX rendering, and meet the license policy
    from ._licenses import license_problems  # ruff: ignore[import-outside-top-level] # parses with the optional extra
    from ._schemas import schema_error, spdx_problems  # ruff: ignore[import-outside-top-level] # the optional extra loads on first use

    loaded: Final = json.loads(raw)
    if census := _census_problems(loaded, max_components):
        return census
    if error := schema_error(loaded):
        return [f"does not conform to the CycloneDX 1.6 schema: {error}"]
    # python-sbom names its file in a metadata property, so documents other tools wrote get the schema check alone; the
    # schema already guarantees the shape of what this reads
    if not any(
        prop.get("name", "").endswith(f":{SBOM_FILE}") for prop in loaded.get("metadata", {}).get("properties", [])
    ):
        return []
    missing: Final[list[str]] = [".".join(path) for path in _REQUIRED if not _has(loaded, path)]
    # is_document holds once nothing is missing; asking it narrows the loaded JSON to a document
    if missing or not is_document(loaded):
        return [f"lacks {', '.join(missing)}, which every document python-sbom writes carries"]
    # optional in the CycloneDX spec itself, but actions/attest's format sniffer requires it to recognize the document
    # as CycloneDX at all, and silently rejects anything missing it as an unknown format
    if not _SERIAL.fullmatch(serial := loaded.get("serialNumber", "")):
        return [f"serialNumber must be a urn:uuid: RFC 4122 UUID, got {serial!r}"]
    # the SPDX rendering of a document whose references are broken only repeats those problems
    problems: Final[list[str]] = _reference_problems(loaded) or spdx_problems(render_spdx(loaded, __version__))
    if allowed_licenses is not None:
        problems.extend(license_problems(loaded["components"], allowed_licenses))
    return problems


def _census_problems(document: _Json, max_components: int) -> list[str]:
    # counts the components and bom-refs and measures the depth in one linear pass before the schema vouches for any
    # shape; iterative, so deep nesting cannot exhaust the stack. Nested components count too: the schema checks every
    # components array, and one array may hold them all, so only the total bounds its work
    components = 0
    refs: Final[Counter[str]] = Counter()
    pending: Final[list[tuple[_Json, int]]] = [(document, 1)]
    while pending:
        node, depth = pending.pop()
        if depth > _MAX_DEPTH:
            return [f"nests more than {_MAX_DEPTH} levels deep, too deep to check"]
        if isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
        elif isinstance(node, dict):
            if isinstance(ref := node.get("bom-ref"), str):
                refs[ref] += 1
            if isinstance(listed := node.get("components"), list):
                components += len(listed)
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, float) and not math.isfinite(node):
            # json.loads takes NaN and Infinity, which RFC 8259 leaves out of JSON and the schema check reads as null
            return [f"holds {node}, which is not a JSON number"]
        if components > max_components:
            problem = (
                f"lists more than {max_components} components, nested ones included;"
                " pass a higher --max-components to check it"
            )
            return [problem]
    if duplicates := sorted(ref for ref, count in refs.items() if count > 1):
        return [f"bom-ref values are not unique: {duplicates}"]
    return []


def _has(value: _Json, path: tuple[str, ...]) -> bool:
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    return True


def is_document(value: object) -> TypeIs[Document]:
    # what the SPDX rendering reads without a fallback; the schema leaves even these optional
    return isinstance(value, dict) and all(_has(value, ("metadata", "component", key)) for key in ("bom-ref", "name"))


def _reference_problems(document: Document) -> list[str]:
    root: Final[Component] = document["metadata"]["component"]
    tools: Final[list[Component]] = document["metadata"]["tools"]["components"]
    components: Final[list[Component]] = _walk([root, *document["components"], *tools])
    if nameless := sorted(component["name"] for component in components if "bom-ref" not in component):
        return [f"components lack a bom-ref: {nameless}"]
    problems: Final[list[str]] = []
    dependencies: Final[dict[str, set[str]]] = {
        entry["ref"]: set(entry.get("dependsOn", [])) for entry in document["dependencies"]
    }
    refs: Final[set[str]] = {component["bom-ref"] for component in components}
    if unknown := (set(dependencies) | set().union(*dependencies.values())) - refs:
        problems.append(f"dependencies reference bom-refs that do not exist: {sorted(unknown)}")
    direct: Final[set[str]] = {component["bom-ref"] for component in document["components"]}
    if dependencies.get(root["bom-ref"]) != direct:
        problems.append(
            f"root dependsOn {sorted(dependencies.get(root['bom-ref'], []))} != components {sorted(direct)}"
        )
    tool_refs: Final[set[str]] = {tool["bom-ref"] for tool in tools}
    for formula in document.get("formulation", []):
        for workflow in formula.get("workflows", []):
            # a workflow may also name an external resource, which no tool can be
            referenced = {
                reference["ref"] for reference in workflow.get("resourceReferences", []) if "ref" in reference
            }
            if unknown := referenced - tool_refs:
                problems.append(f"workflow {workflow['uid']} references unknown tools: {sorted(unknown)}")
    return problems


def _walk(components: list[Component]) -> list[Component]:
    # iterative, so a deeply nested hostile document cannot exhaust the stack
    found: Final[list[Component]] = []
    pending: Final[list[Component]] = list(components)
    while pending:
        component = pending.pop()
        found.append(component)
        pending.extend(component.get("components", []))
    return found


__all__ = [
    "MAX_COMPONENTS",
    "is_document",
    "validate_document",
]
