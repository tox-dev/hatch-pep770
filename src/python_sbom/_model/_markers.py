from __future__ import annotations

from typing import TYPE_CHECKING

from dep_logic.markers import from_pkg_marker

if TYPE_CHECKING:
    from packaging.requirements import Requirement


def applies_without_extras(requirement: Requirement) -> bool:
    # dep-logic reduces the marker to its conditions on extra, holding where some environment satisfies the rest, so
    # the requirement applies unless they fail with no extra requested; a marker no environment satisfies never applies
    if requirement.marker is None:
        return True
    try:
        return from_pkg_marker(requirement.marker).only("extra").evaluate({"extra": ""})
    # dep-logic asserts extra is compared through == or != only; listing such a requirement beats leaving it out
    except AssertionError:
        return True


__all__ = [
    "applies_without_extras",
]
