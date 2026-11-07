"""Check an SBOM against the CycloneDX 1.6 schema, its own references, its SPDX rendering and a license policy."""

from __future__ import annotations

import json
import re
import zipfile
from typing import TYPE_CHECKING, Final

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

from .spdx import to_spdx

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from .cyclonedx import Component, Document, License

_SERIAL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""
    ^urn:uuid:
    (?P<time_low>[0-9a-f]{8})-
    (?P<time_mid>[0-9a-f]{4})-
    (?P<time_high_and_version>[0-9a-f]{4})-
    (?P<clock_seq>[0-9a-f]{4})-
    (?P<node>[0-9a-f]{12})
    $
    """,
    re.VERBOSE,
)
# SPDX matches operators only in upper case
_OPERATORS: Final[frozenset[str]] = frozenset({"AND", "OR", "WITH", "(", ")"})
_TOKEN: Final[re.Pattern[str]] = re.compile(r"[()]|[^\s()]+")


def wheel_problems(wheel: Path, allowed_licenses: frozenset[str] | None) -> list[str]:
    """
    Check every PEP 770 CycloneDX SBOM in a wheel.

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
    return [f"{name}: {problem}" for name, raw in sboms.items() for problem in document_problems(raw, allowed_licenses)]


def document_problems(raw: str, allowed_licenses: frozenset[str] | None) -> list[str]:
    """
    Check one CycloneDX SBOM.

    Beyond the schema it requires the ``urn:uuid`` serial number ``actions/attest`` needs to recognize the format,
    unique and resolvable ``bom-ref`` values, a root that depends on exactly the top-level components, and an SPDX 2.3
    rendering that validates.

    :param raw: the JSON text of the document
    :param allowed_licenses: SPDX license ids the shipped components may use, or ``None`` to skip the license policy
    :returns: one message per problem, empty when the document is valid

    """
    if schema_error := JsonStrictValidator(SchemaVersion.V1_6).validate_str(raw):
        return [f"does not conform to the CycloneDX 1.6 schema: {schema_error}"]
    document: Final[Document] = json.loads(raw)
    if problems := _serial_problems(document.get("serialNumber", "")):
        return problems
    problems = _reference_problems(document)
    problems += _spdx_problems(document)
    if allowed_licenses is not None:
        problems += license_problems(document["components"], allowed_licenses)
    return problems


def _serial_problems(serial: str) -> list[str]:
    # optional in the CycloneDX spec itself, but actions/attest's format sniffer requires it to recognize the document
    # as CycloneDX at all, and silently rejects anything missing it as an unknown format
    return [] if _SERIAL_PATTERN.match(serial) else [f"serialNumber must be a urn:uuid: RFC 4122 UUID, got {serial!r}"]


def _reference_problems(document: Document) -> list[str]:
    root_ref = document["metadata"]["component"]["bom-ref"]
    tools = document["metadata"]["tools"]["components"]
    every_ref = list(_bom_refs([document["metadata"]["component"], *document["components"], *tools]))
    if duplicates := {ref for ref in every_ref if every_ref.count(ref) > 1}:
        return [f"bom-ref values are not unique: {sorted(duplicates)}"]
    problems = []
    dependencies = {entry["ref"]: set(entry["dependsOn"]) for entry in document["dependencies"]}
    if unknown := (set(dependencies) | set().union(*dependencies.values())) - set(every_ref):
        problems.append(f"dependencies reference bom-refs that do not exist: {sorted(unknown)}")
    if dependencies.get(root_ref) != (component_refs := {component["bom-ref"] for component in document["components"]}):
        problems.append(
            f"root dependsOn {sorted(dependencies.get(root_ref, []))} != components {sorted(component_refs)}"
        )
    tool_refs = {tool["bom-ref"] for tool in tools}
    problems.extend(
        f"workflow {workflow['uid']} references unknown tools: {sorted(unknown)}"
        for workflow in (workflow for formula in document["formulation"] for workflow in formula["workflows"])
        if (unknown := {reference["ref"] for reference in workflow["resourceReferences"]} - tool_refs)
    )
    return problems


def _bom_refs(components: list[Component]) -> Iterator[str]:
    for component in components:
        yield component["bom-ref"]
        yield from _bom_refs(component.get("components", []))


def _spdx_problems(document: Document) -> list[str]:
    try:
        spdx = JsonLikeDictParser().parse(dict(to_spdx(document)))
    except SPDXParsingError as error:
        return [f"SPDX rendering does not parse: {message}" for message in error.get_messages()]
    return [f"SPDX rendering invalid: {message.validation_message}" for message in validate_full_spdx_document(spdx)]


def license_problems(components: list[Component], allowed_licenses: frozenset[str]) -> list[str]:
    """
    Judge the licenses of what an artifact ships against a policy.

    Only components the artifact carries bytes for are judged: a bundled wheel, or a component with files. A declared
    requirement resolves at install time, and a library a bundled wheel vendors ships under that wheel's terms.

    :param components: the document's top-level components
    :param allowed_licenses: SPDX license ids a shipped component may use; an expression passes when the ids it needs
        are allowed, and ``WITH`` exceptions only grant extra permissions so the license they modify decides
    :returns: one message per component that fails the policy

    """
    return [
        f"{component['bom-ref']}: {problem}"
        for component in _shipped(components)
        if (problem := _judge(component, allowed_licenses))
    ]


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
    "document_problems",
    "license_problems",
    "wheel_problems",
]
