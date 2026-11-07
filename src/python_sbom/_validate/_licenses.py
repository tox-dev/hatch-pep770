from __future__ import annotations

import re
from itertools import accumulate
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from python_sbom._model._types import Component, License

# SPDX matches operators only in upper case
_OPERATORS: Final[frozenset[str]] = frozenset({"AND", "OR", "WITH", "(", ")"})
_TOKEN: Final[re.Pattern[str]] = re.compile(r"[()]|[^\s()]+")
# the parser spends three stack frames per parenthesis, and real expressions nest a level or two
_MAX_NESTING: Final[int] = 32


def license_problems(components: list[Component], allowed: frozenset[str]) -> list[str]:
    return [
        f"{component.get('bom-ref', component['name'])}: {problem}"
        for component in _shipped(components)
        if (problem := _judge(component, allowed))
    ]


def _shipped(components: list[Component]) -> list[Component]:
    # only what the artifact carries bytes for is judged: a declared requirement resolves at install time, and a
    # library a bundled wheel vendors ships under that wheel's terms; iterative, so deep nesting cannot exhaust the
    # stack
    found: Final[list[Component]] = []
    pending: Final[list[Component]] = list(reversed(components))
    while pending:
        component = pending.pop()
        if component["type"] == "library" and (
            "hashes" in component or any(child["type"] == "file" for child in component.get("components", []))
        ):
            found.append(component)
        pending.extend(reversed(component.get("components", [])))
    return found


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
    denied: Final[list[str]] = []
    for term in terms:
        try:
            if not _allowed(term, allowed):
                denied.append(term)
        except ValueError as error:
            return f"license expression {term!r} is malformed: {error}"
    if denied:
        return f"license {' AND '.join(denied)} is outside the allowed licenses {sorted(allowed)}"
    return None


def _allowed(expression: str, allowed: frozenset[str]) -> bool:
    tokens: Final[list[str]] = _tokens(expression)
    verdict: Final[bool] = _license_any_of(tokens, allowed)
    if tokens:
        msg: Final[str] = f"unexpected {tokens[-1]!r}"
        raise ValueError(msg)
    return verdict


def _tokens(expression: str) -> list[str]:
    found: Final[list[str]] = _TOKEN.findall(expression)
    if (depth := max(accumulate({"(": 1, ")": -1}.get(token, 0) for token in found), default=0)) > _MAX_NESTING:
        msg: Final[str] = f"it nests {depth} levels deep, over the {_MAX_NESTING} level limit"
        raise ValueError(msg)
    # reversed, so the parser takes the next token with a cheap pop from the end
    return found[::-1]


def _license_any_of(tokens: list[str], allowed: frozenset[str]) -> bool:
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
        verdict: Final[bool] = _license_any_of(tokens, allowed)
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
    "license_problems",
]
