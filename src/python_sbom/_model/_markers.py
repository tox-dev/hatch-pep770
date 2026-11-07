from __future__ import annotations

from typing import TYPE_CHECKING, Final

from packaging._parser import Op, Value, Variable  # ruff: ignore[import-private-name] # packaging exposes the parsed marker tree only privately
from packaging.markers import Marker

if TYPE_CHECKING:
    from packaging._parser import MarkerAtom, MarkerList  # see above
    from packaging.requirements import Requirement


def applies_without_extras(requirement: Requirement) -> bool:
    # the conditions on extra are decided with no extra requested and every other condition stays unknown, so the
    # requirement applies unless its extra conditions alone rule it out
    if requirement.marker is None:
        return True
    return _extra_verdict(requirement.marker._markers) is not False  # ruff: ignore[private-member-access] # the tree, see the import above


def _extra_verdict(markers: MarkerList | MarkerAtom) -> bool | None:
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
                    groups[-1].append(Marker(f"extra {operator} {value!r}").evaluate({"extra": ""}))
                case Value(value=value), Op(value=operator), Variable(value="extra"):
                    groups[-1].append(Marker(f"{value!r} {operator} extra").evaluate({"extra": ""}))
                case _:
                    groups[-1].append(None)
    # ranked False < unknown < True: "and" takes the lowest verdict of a group, "or" the highest of the groups
    verdicts: Final[tuple[bool | None, ...]] = (False, None, True)
    return verdicts[max(min(map(verdicts.index, group), default=2) for group in groups)]


__all__ = [
    "applies_without_extras",
]
