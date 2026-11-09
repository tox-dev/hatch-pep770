"""
The pdm-backend build hook, which writes the SBOM into every wheel pdm-backend builds.

pdm-backend loads it from the ``pdm.build.hook`` entry point group whenever python-sbom is installed in the build
environment, so it acts only for a project whose ``pyproject.toml`` has a ``[tool.python-sbom]`` table, empty or not.
"""

from __future__ import annotations

import calendar
from pathlib import Path
from typing import TYPE_CHECKING

from ._collect._revision import REVISION_FILE, default_revision, revision_record

if TYPE_CHECKING:
    from pdm.backend.hooks import Context

    from ._model._inputs import Revision


class SbomBuildHook:
    """Write the SBOM into a wheel pdm-backend built, and record the source revision in an sdist."""

    _revision: Revision | None = None

    def pdm_build_hook_enabled(self, context: Context) -> bool:  # ruff: ignore[no-self-use] # pdm-backend calls it on the hook
        """
        Act only on a project that asks for an SBOM.

        :param context: pdm-backend's build context
        :returns: whether ``[tool.python-sbom]`` exists and the build is a wheel or an sdist

        """
        return context.target in {"sdist", "wheel"} and "python-sbom" in context.config.data.get("tool", {})

    def pdm_build_initialize(self, context: Context) -> None:
        """
        Read the source revision, before the build writes into the checkout.

        :param context: pdm-backend's build context

        """
        self._revision = default_revision(context.root)

    def pdm_build_update_files(self, context: Context, files: dict[str, Path]) -> None:
        """
        Add the source revision to an sdist, so a wheel built from it still names its commit.

        :param context: pdm-backend's build context
        :param files: the files the artifact will hold, by their path in it

        """
        if context.target != "sdist" or (record := revision_record(self._revision)) is None:
            return
        # in pdm-backend's own build directory, which it ignores in git and cleans
        (written := context.ensure_build_dir() / REVISION_FILE).write_bytes(record)
        files[REVISION_FILE] = written

    def pdm_build_finalize(self, context: Context, artifact: Path) -> None:
        """
        Write the SBOM into the wheel pdm-backend built.

        :param context: pdm-backend's build context
        :param artifact: the built wheel or sdist

        """
        if context.target != "wheel":
            return
        # what a wheel needs loads only when one is built, so an sdist build stays light
        from pdm.backend.wheel import ZIPINFO_DATE_TIME  # ruff: ignore[import-outside-top-level] # see above

        from ._generate._embed import embed_built  # ruff: ignore[import-outside-top-level] # see above

        # pdm-backend dates every zip entry at a fixed time when SOURCE_DATE_EPOCH is unset, so the SBOM agrees
        embed_built(Path(artifact), context.root, self._revision, default_epoch=calendar.timegm(ZIPINFO_DATE_TIME))


__all__ = [
    "SbomBuildHook",
]
