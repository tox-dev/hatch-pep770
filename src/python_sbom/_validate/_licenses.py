"""Check the licenses of the libraries an artifact ships against the allowed SPDX ids."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from license_expression import (
    AND,
    ExpressionError,
    LicenseSymbol,
    LicenseWithExceptionSymbol,
    Licensing,
    get_license_index,
)

from python_sbom._model._graph import shipped_libraries

if TYPE_CHECKING:
    from license_expression import LicenseExpression

    from python_sbom._model._types import Component, License

# the SPDX ids alone, without the aliases get_spdx_licensing() adds: those rename ids (LicenseRef-Apache becomes
# Apache-2.0, Net-SNMP becomes LicenseRef-scancode-net-snmp), so a policy would judge an id other than the one declared;
# knowing the ids still lets the parser tell "MIT ISC" apart from a single license
_LICENSING: Final[Licensing] = Licensing(
    LicenseSymbol(entry["spdx_license_key"], is_exception=entry["is_exception"])
    for entry in get_license_index()
    if entry.get("spdx_license_key")
)


def license_problems(contents: list[Component], allowed: frozenset[str]) -> list[str]:
    # SPDX matches license ids without regard to case
    folded: Final[frozenset[str]] = frozenset(identifier.casefold() for identifier in allowed)
    return [
        f"{component.get('bom-ref', component['name'])}: {problem}"
        for component in shipped_libraries(contents)
        if (problem := _judge(component, allowed, folded))
    ]


def _judge(component: Component, allowed: frozenset[str], folded: frozenset[str]) -> str | None:
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
    denied: Final[list[str]] = []
    for term in terms:
        try:
            tree = _parse(term)
        except ValueError as error:
            return f"license expression {term!r} is malformed: {error}"
        if not _allowed(tree, folded):
            denied.append(term)
    if denied:
        return f"license {' AND '.join(denied)} is outside the allowed licenses {sorted(allowed)}"
    return None


def _parse(term: str) -> LicenseExpression:
    try:
        tree: Final[LicenseExpression | None] = _LICENSING.parse(term)
    except ExpressionError as error:
        raise ValueError(str(error)) from error
    except (AssertionError, IndexError) as error:
        # boolean.py trips over some malformed input, such as "( OR MIT" or "()", before it reports it
        msg = "it does not parse"
        raise ValueError(msg) from error
    if tree is None:
        msg = "it is empty"
        raise ValueError(msg)
    return tree


def _allowed(tree: LicenseExpression, folded: frozenset[str]) -> bool:
    # the parse tree nests as deep as the expression does, so it is walked with a stack instead of recursion; children
    # come after their parent in this order, so the reversed walk judges them first
    order: Final[list[LicenseExpression]] = []
    pending: Final[list[LicenseExpression]] = [tree]
    while pending:
        order.append(node := pending.pop())
        pending.extend(node.args)
    verdicts: Final[dict[int, bool]] = {}
    for node in reversed(order):
        if isinstance(node, LicenseWithExceptionSymbol):
            # an exception grants extra permissions on top of the license it modifies, so that license alone decides
            verdicts[id(node)] = node.license_symbol.key.casefold() in folded
        elif isinstance(node, LicenseSymbol):
            verdicts[id(node)] = node.key.casefold() in folded
        else:
            # the parser builds only AND and OR around the symbols
            branches = (verdicts[id(arg)] for arg in node.args)
            verdicts[id(node)] = all(branches) if isinstance(node, AND) else any(branches)
    return verdicts[id(tree)]


__all__ = [
    "license_problems",
]
