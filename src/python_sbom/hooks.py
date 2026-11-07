"""Register the build hook with hatchling."""

from __future__ import annotations

from hatchling.plugin import hookimpl

from ._hook import SbomBuildHook


@hookimpl
def hatch_register_build_hook() -> type[SbomBuildHook]:
    """
    Return the build hook hatchling loads for ``[tool.hatch.build.hooks.python-sbom]``.

    :returns: the build hook class

    """
    return SbomBuildHook
