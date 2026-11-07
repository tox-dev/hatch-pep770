"""Register the build hook with hatchling."""

from __future__ import annotations

from hatchling.plugin import hookimpl

from ._hook import Pep770BuildHook


@hookimpl
def hatch_register_build_hook() -> type[Pep770BuildHook]:
    """
    Return the build hook hatchling loads for ``[tool.hatch.build.hooks.pep770]``.

    :returns: the build hook class

    """
    return Pep770BuildHook
