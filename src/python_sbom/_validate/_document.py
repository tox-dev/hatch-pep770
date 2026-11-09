"""Check an SBOM's size, nesting and schema, and in one python-sbom wrote, its serial, references, SPDX and licenses."""

from __future__ import annotations

import math
import re
from importlib.util import find_spec
from typing import TYPE_CHECKING, Final

from python_sbom._errors import MissingExtraError, SbomError
from python_sbom._formats._json import Json, has_path, is_document, load_json
from python_sbom._formats._spdx import render_spdx
from python_sbom._model._graph import artifact_contents, reference_problems, repeated, walk_components
from python_sbom._model._names import SBOM_FILE

from ._limits import MAX_COMPONENTS, MAX_TEXT, byte_limit

if TYPE_CHECKING:
    from collections.abc import Iterable

    from python_sbom._model._types import Component, Document

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
# the modules of the validate extra
_EXTRA: Final[tuple[str, ...]] = ("jsonschema_rs", "license_expression", "spdx_tools")
# the schema validator recurses once per level and crashes the process past a few thousand levels on a small thread
# stack; the SBOMs python-sbom and other tools write nest about a dozen levels deep
_MAX_DEPTH: Final[int] = 128


def validate_document(
    raw: bytes, allowed_licenses: frozenset[str] | None, max_components: int = MAX_COMPONENTS
) -> list[str]:
    if len(raw) > (limit := byte_limit(max_components)):
        problem = (
            f"is over {limit} bytes, the size limit for {max_components} components;"
            " pass a higher --max-components to check it"
        )
        return [problem]
    # one document's problem never stops the others from being checked, so whatever the checks raise is reported
    try:
        return _problems(raw, allowed_licenses, max_components)
    except MissingExtraError:
        raise
    except SbomError as error:
        return [str(error)]
    except Exception as error:  # ruff: ignore[blind-except] # a hostile document may trip any check, see above
        return [f"could not be checked, {type(error).__name__}: {str(error)[:MAX_TEXT]}"]


def _problems(raw: bytes, allowed_licenses: frozenset[str] | None, max_components: int) -> list[str]:
    # every document must conform to the CycloneDX 1.6 schema; one python-sbom wrote must also carry the urn:uuid serial
    # actions/attest needs, resolvable and unique bom-refs and a valid SPDX rendering, and meet the license policy. A
    # missing extra fails every document alike, while importing it, half a second, waits until the cheap census passes
    missing_extra: Final[str] = "validation needs the validate extra: pip install 'python-sbom[validate]'"
    if any(find_spec(name) is None for name in _EXTRA):
        raise MissingExtraError(missing_extra)
    loaded: Final = load_json(raw)
    if census := _census_problems(loaded, max_components):
        return census
    # find_spec sees only the top-level modules, not a dependency of theirs that is missing or broken
    try:
        from ._schemas import schema_error, spdx_problems  # ruff: ignore[import-outside-top-level] # the optional extra, see above
    except ImportError as error:
        raise MissingExtraError(missing_extra) from error

    if error := schema_error(loaded):
        return [f"does not conform to the CycloneDX 1.6 schema: {error}"]
    # python-sbom names its file in a metadata property, so documents other tools wrote get the schema check alone; the
    # schema already guarantees the shape of what this reads
    if not any(
        prop.get("name", "").endswith(f":{SBOM_FILE}") for prop in loaded.get("metadata", {}).get("properties", [])
    ):
        return []
    missing: Final[list[str]] = [".".join(path) for path in _REQUIRED if not has_path(loaded, path)]
    # is_document holds once nothing is missing; asking it narrows the loaded JSON to a document
    if missing or not is_document(loaded):
        return [f"lacks {', '.join(missing)}, which every document python-sbom writes carries"]
    # optional in the CycloneDX spec itself, but actions/attest's format sniffer requires it to recognize the document
    # as CycloneDX at all, and silently rejects anything missing it as an unknown format
    if not _SERIAL.fullmatch(serial := loaded.get("serialNumber", "")):
        return [f"serialNumber must be a urn:uuid: RFC 4122 UUID, got {serial!r}"]
    # the SPDX rendering of a document whose references are broken only repeats those problems
    problems: Final[list[str]] = _reference_problems(loaded) or spdx_problems(render_spdx(loaded))
    if allowed_licenses is not None:
        # the license parser loads only for a policy to judge against, as most checks have none
        try:
            from ._licenses import license_problems  # ruff: ignore[import-outside-top-level] # see above
        except ImportError as error:
            raise MissingExtraError(missing_extra) from error
        problems.extend(
            license_problems(artifact_contents(loaded["metadata"]["component"], loaded["components"]), allowed_licenses)
        )
    return problems


def _census_problems(document: Json, max_components: int) -> list[str]:
    # counts the components and bom-refs and measures the depth in one linear pass before the schema vouches for any
    # shape; iterative, so deep nesting cannot exhaust the stack. Nested components count too: the schema checks every
    # components array, and one array may hold them all, so only the total bounds its work
    components = 0
    refs: Final[list[str]] = []
    # only lists and objects go on the stack, every other value is judged where its container is read, so a scalar
    # nests too deep when its container already sits at the limit; the document starts out as the one item of a list
    pending: Final[list[tuple[list[Json] | dict[str, Json], int]]] = [([document], 0)]
    while pending:
        node, depth = pending.pop()
        if isinstance(node, dict):
            if isinstance(ref := node.get("bom-ref"), str):
                refs.append(ref)
            components += len(listed) if isinstance(listed := node.get("components"), list) else 0
        if components > max_components:
            return [
                (
                    f"lists more than {max_components} components, nested ones included;"
                    " pass a higher --max-components to check it"
                )
            ]
        children = node.values() if isinstance(node, dict) else node
        if children and depth >= _MAX_DEPTH:
            return [f"nests more than {_MAX_DEPTH} levels deep, too deep to check"]
        if problem := _push_containers(children, depth + 1, pending):
            return problem
    # every bom-ref in the document, wherever it sits, as CycloneDX requires them unique and documents other tools wrote
    # get no reference check beyond this
    if twice := repeated(refs):
        return [f"bom-ref values repeat: {', '.join(twice)}"]
    return []


def _push_containers(
    children: Iterable[Json], depth: int, pending: list[tuple[list[Json] | dict[str, Json], int]]
) -> list[str]:
    for child in children:
        if isinstance(child, (list, dict)):
            pending.append((child, depth))
        elif isinstance(child, float) and not math.isfinite(child):
            # json.loads takes NaN and Infinity, which RFC 8259 leaves out of JSON and the schema reads as null
            return [f"holds {child}, which is not a JSON number"]
    return []


def _reference_problems(document: Document) -> list[str]:
    root: Final[Component] = document["metadata"]["component"]
    tools: Final[list[Component]] = document["metadata"]["tools"]["components"]
    components: Final[list[Component]] = list(walk_components([root, *document["components"], *tools]))
    if nameless := sorted(component["name"] for component in components if "bom-ref" not in component):
        return [f"components lack a bom-ref: {nameless}"]
    formulas: Final[list[str]] = [
        ref
        for formula in document.get("formulation", [])
        for ref in (formula["bom-ref"], *(workflow["bom-ref"] for workflow in formula.get("workflows", [])))
    ]
    if problems := reference_problems(
        [*(component["bom-ref"] for component in components), *formulas], document["dependencies"]
    ):
        return problems
    problems: Final[list[str]] = []
    dependencies: Final[dict[str, set[str]]] = {
        entry["ref"]: set(entry.get("dependsOn", [])) for entry in document["dependencies"]
    }
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


__all__ = [
    "validate_document",
]
