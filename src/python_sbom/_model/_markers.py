"""Decide whether a requirement applies when no extra is selected."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from packaging.markers import Marker, UndefinedComparison

if TYPE_CHECKING:
    from packaging._parser import MarkerAtom, MarkerList  # see _extra_verdict
    from packaging.requirements import Requirement


def applies_without_extras(requirement: Requirement) -> bool:
    # the conditions on extra are decided with no extra requested and every other condition stays unknown, so the
    # requirement applies unless its extra conditions alone rule it out; dep-logic reduces markers the same way, but it
    # rejects extra comparisons other than == and != through assert, which python -O strips, and on import it replaces
    # packaging's marker grammar for the whole build process
    if requirement.marker is None:
        return True
    try:
        verdict = _extra_verdict(requirement.marker._markers)  # ruff: ignore[private-member-access] # see _extra_verdict
    # packaging keeps the parsed tree private, so a release that moves or renames it leaves the requirement listed
    # rather than dropping one that applies
    except (AttributeError, ImportError):
        return True
    return verdict is not False


def _extra_verdict(markers: MarkerList | MarkerAtom) -> bool | None:
    from packaging._parser import Op, Value, Variable  # ruff: ignore[import-private-name, import-outside-top-level] # packaging keeps the marker tree private, the caller handles its absence

    # three-valued, with "and" binding tighter than "or", as packaging's own evaluation groups them
    groups: list[list[bool | None]] = [[]]
    for item in markers:
        if item == "or":
            groups.append([])
        elif isinstance(item, list):
            groups[-1].append(_extra_verdict(item))
        elif isinstance(item, tuple):
            match item:
                case Variable(value="extra"), Op(value=operator), Value(value=value):
                    groups[-1].append(_no_extra_verdict(f"extra {operator} {value!r}"))
                case Value(value=value), Op(value=operator), Variable(value="extra"):
                    groups[-1].append(_no_extra_verdict(f"{value!r} {operator} extra"))
                case _:
                    groups[-1].append(None)
    # ranked False < unknown < True: "and" takes the lowest verdict of a group, "or" the highest of the groups
    verdicts: Final[tuple[bool | None, ...]] = (False, None, True)
    return verdicts[max(min(map(verdicts.index, group), default=2) for group in groups)]


def _no_extra_verdict(condition: str) -> bool | None:
    try:
        return Marker(condition).evaluate({"extra": ""})
    # extra compared as a version, such as extra ~= "1.0", has no answer, so it stays unknown
    except UndefinedComparison:
        return None


__all__ = [
    "applies_without_extras",
]
