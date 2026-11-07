from __future__ import annotations

import json
import re
import zipfile
from typing import TYPE_CHECKING, Final, TypeAlias

from python_sbom._formats._spdx import to_spdx

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from python_sbom._model._types import Component, Document, License

#: a JSON value, as :func:`json.loads` hands it over
Json: TypeAlias = "str | int | float | bool | list[Json] | dict[str, Json] | None"
# SPDX matches operators only in upper case
_OPERATORS: Final[frozenset[str]] = frozenset({"AND", "OR", "WITH", "(", ")"})
_TOKEN: Final[re.Pattern[str]] = re.compile(r"[()]|[^\s()]+")


def validate_wheel(wheel: Path, allowed_licenses: frozenset[str] | None) -> list[str]:
    """
    Check every PEP 770 CycloneDX SBOM in a wheel; needs the ``validate`` extra.

    :param wheel: the wheel to read
    :param allowed_licenses: SPDX license ids the shipped components may use, or ``None`` to skip the license policy
    :returns: one message per problem, empty when the wheel carries at least one SBOM and every SBOM is valid

    """
    with zipfile.ZipFile(wheel) as archive:
        sboms = {
            name: archive.read(name).decode("utf-8")
            for name in sorted(archive.namelist())
            if re.fullmatch(r"[^/]+\.dist-info/sboms/[^/]+\.cdx\.json", name)
        }
    if not sboms:
        return ["no .dist-info/sboms/*.cdx.json found in the wheel"]
    return [f"{name}: {problem}" for name, raw in sboms.items() for problem in validate(raw, allowed_licenses)]


def validate(raw: str, allowed_licenses: frozenset[str] | None) -> list[str]:
    """
    Check one CycloneDX SBOM; needs the ``validate`` extra.

    Beyond the schema it requires the ``urn:uuid`` serial number ``actions/attest`` needs to recognize the format,
    unique and resolvable ``bom-ref`` values, a root that depends on exactly the top-level components, and an SPDX 2.3
    rendering that validates.

    :param raw: the JSON text of the document
    :param allowed_licenses: SPDX license ids the shipped components may use, or ``None`` to skip the license policy
    :returns: one message per problem, empty when the document is valid

    """
    from ._schemas import schema_error, spdx_problems  # ruff: ignore[import-outside-top-level]  # optional extra

    if error := schema_error(raw):
        return [f"does not conform to the CycloneDX 1.6 schema: {error}"]
    loaded: Json = json.loads(raw)
    # the schema leaves these optional, yet the checks below and the SPDX rendering read them
    required: tuple[tuple[str, ...], ...] = (
        ("metadata", "timestamp"),
        ("metadata", "tools", "components"),
        ("metadata", "component", "bom-ref"),
        ("metadata", "component", "name"),
        ("components",),
        ("dependencies",),
    )
    if missing := [".".join(path) for path in required if not _has(loaded, path)]:
        return [f"lacks {', '.join(missing)}, which every document python-sbom writes carries"]
    document: Final[Document] = json.loads(raw)
    # optional in the CycloneDX spec itself, but actions/attest's format sniffer requires it to recognize the document
    # as CycloneDX at all, and silently rejects anything missing it as an unknown format
    if not re.fullmatch(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        serial := document.get("serialNumber", ""),
    ):
        return [f"serialNumber must be a urn:uuid: RFC 4122 UUID, got {serial!r}"]
    problems = _reference_problems(document)
    problems.extend(spdx_problems(to_spdx(document)))
    if allowed_licenses is not None:
        # only what the artifact carries bytes for is judged: a declared requirement resolves at install time, and a
        # library a bundled wheel vendors ships under that wheel's terms
        problems.extend(
            f"{component['bom-ref']}: {problem}"
            for component in _shipped(document["components"])
            if (problem := _judge(component, allowed_licenses))
        )
    return problems


def _has(value: Json, path: tuple[str, ...]) -> bool:
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    return True


def _reference_problems(document: Document) -> list[str]:
    root_ref = document["metadata"]["component"]["bom-ref"]
    tools = document["metadata"]["tools"]["components"]
    every_ref = list(_bom_refs([document["metadata"]["component"], *document["components"], *tools]))
    if duplicates := {ref for ref in every_ref if every_ref.count(ref) > 1}:
        return [f"bom-ref values are not unique: {sorted(duplicates)}"]
    dependencies = {entry["ref"]: set(entry.get("dependsOn", [])) for entry in document["dependencies"]}
    problems = []
    if unknown := (set(dependencies) | set().union(*dependencies.values())) - set(every_ref):
        problems.append(f"dependencies reference bom-refs that do not exist: {sorted(unknown)}")
    if dependencies.get(root_ref) != (component_refs := {component["bom-ref"] for component in document["components"]}):
        problems.append(
            f"root dependsOn {sorted(dependencies.get(root_ref, []))} != components {sorted(component_refs)}"
        )
    tool_refs = {tool["bom-ref"] for tool in tools}
    problems.extend(
        f"workflow {workflow['uid']} references unknown tools: {sorted(unknown)}"
        for workflow in (workflow for formula in document.get("formulation", []) for workflow in formula["workflows"])
        if (unknown := {reference["ref"] for reference in workflow["resourceReferences"]} - tool_refs)
    )
    return problems


def _bom_refs(components: list[Component]) -> Iterator[str]:
    for component in components:
        yield component["bom-ref"]
        yield from _bom_refs(component.get("components", []))


def _shipped(components: list[Component]) -> Iterator[Component]:
    for component in components:
        if component["type"] == "library" and (
            "hashes" in component or any(child["type"] == "file" for child in component.get("components", []))
        ):
            yield component
        yield from _shipped(component.get("components", []))


def _judge(component: Component, allowed: frozenset[str]) -> str | None:
    licenses: Final[list[License]] = component.get("licenses", [])
    terms: Final[list[str]] = [
        entry["expression"] if "expression" in entry else entry["license"]["id"]
        for entry in licenses
        if "expression" in entry or "id" in entry["license"]
    ]
    if not terms:
        if names := [entry["license"]["name"] for entry in licenses if "license" in entry]:
            return f"declares license names {names} with no SPDX id"
        return "declares no license"
    try:
        denied: Final[list[str]] = [term for term in terms if not _allowed(term, allowed)]
    except ValueError as error:
        return str(error)
    if denied:
        return f"license {' AND '.join(denied)} is outside the allowed licenses {sorted(allowed)}"
    return None


def _allowed(expression: str, allowed: frozenset[str]) -> bool:
    tokens: Final[list[str]] = _TOKEN.findall(expression)[::-1]
    try:
        verdict: Final[bool] = _any_of(tokens, allowed)
    except ValueError as error:
        msg = f"license expression {expression!r} is malformed: {error}"
        raise ValueError(msg) from error
    if tokens:
        msg = f"license expression {expression!r} is malformed: unexpected {tokens[-1]!r}"
        raise ValueError(msg)
    return verdict


def _any_of(tokens: list[str], allowed: frozenset[str]) -> bool:
    verdict = _all_of(tokens, allowed)
    while tokens and tokens[-1] == "OR":
        tokens.pop()
        verdict |= _all_of(tokens, allowed)
    return verdict


def _all_of(tokens: list[str], allowed: frozenset[str]) -> bool:
    verdict = _term(tokens, allowed)
    while tokens and tokens[-1] == "AND":
        tokens.pop()
        verdict &= _term(tokens, allowed)
    return verdict


def _term(tokens: list[str], allowed: frozenset[str]) -> bool:
    if (token := _pop(tokens)) == "(":
        verdict: Final[bool] = _any_of(tokens, allowed)
        if (closing := _pop(tokens)) != ")":
            msg = f"expected ')', got {closing!r}"
            raise ValueError(msg)
        return verdict
    if token in _OPERATORS:
        msg = f"unexpected {token!r}"
        raise ValueError(msg)
    if tokens and tokens[-1] == "WITH":
        tokens.pop()
        # an exception grants extra permissions on top of the license it modifies, so that license alone decides
        if (exception := _pop(tokens)) in _OPERATORS:
            msg = f"unexpected {exception!r}"
            raise ValueError(msg)
    # SPDX matches license ids without regard to case
    return token.casefold() in {identifier.casefold() for identifier in allowed}


def _pop(tokens: list[str]) -> str:
    if not tokens:
        msg: Final[str] = "it ends early"
        raise ValueError(msg)
    return tokens.pop()


__all__ = [
    "validate",
    "validate_wheel",
]
