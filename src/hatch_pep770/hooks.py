"""Register the build hook with hatchling."""

from __future__ import annotations

from hatchling.plugin import hookimpl

from .plugin import Pep770BuildHook


@hookimpl
def hatch_register_build_hook() -> type[Pep770BuildHook]:
    return Pep770BuildHook


__all__ = [
    "hatch_register_build_hook",
]
