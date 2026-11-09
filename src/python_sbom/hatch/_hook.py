"""The hatchling build hook: record the source revision in an sdist and write the SBOM into a wheel."""

from __future__ import annotations

import shutil
import tempfile
import weakref
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.builders.utils import get_reproducible_timestamp
from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

from python_sbom._collect._content import resolve_provider
from python_sbom._collect._revision import REVISION_FILE, default_revision, revision_record
from python_sbom._collect._settings import settings_from_table
from python_sbom._errors import SbomError

if TYPE_CHECKING:
    from collections.abc import Callable

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._inputs import Settings

# options of every hatchling hook table, which hatchling itself reads
_HATCHLING_OPTIONS: Final[frozenset[str]] = frozenset({
    "dependencies",
    "enable-by-default",
    "path",
    "require-runtime-dependencies",
    "require-runtime-features",
})


class SbomBuildHook(BuildHookInterface):
    """
    Hatchling build hook that writes a CycloneDX SBOM into the wheel's ``.dist-info/sboms/``, as PEP 770 describes.

    It runs once hatchling has written the wheel, so the SBOM describes the wheel's final metadata and file name
    whatever other hooks changed. Options come from ``[tool.python-sbom]``, the one place ``python-sbom embed`` and
    ``python-sbom archive`` read them too. For an sdist it records the source revision, so a wheel built from that sdist
    still names its commit.

    :cvar PLUGIN_NAME: the hook's name in ``[tool.hatch.build.hooks]``

    """

    PLUGIN_NAME = "python-sbom"
    _remove_revision_file: Callable[[], None] | None = None

    def initialize(
        self,
        version: str,
        build_data: dict[str, Any],  # simplint: ignore[SMP602] # hatchling's signature
    ) -> None:
        """
        Read the source revision, and record it in an sdist.

        :param version: hatchling's build variant
        :param build_data: hatchling's build data, which receives the revision file

        """
        if self.target_name not in {"sdist", "wheel"} or version == "editable":
            return
        # once per build, before it writes the artifact into a checkout that may not ignore it; a value kept for the
        # process would name an older commit in the next build after a commit
        self._revision = default_revision(Path(self.root))
        if self.target_name != "sdist" or (record := revision_record(self._revision)) is None:
            return
        # outside the project, so the build leaves nothing behind in it
        directory = tempfile.mkdtemp()
        # hatchling reads the file only while it writes the sdist, and skips finalize when the build fails, so the
        # directory then goes with the hook, at the latest when the interpreter exits
        self._remove_revision_file = weakref.finalize(self, shutil.rmtree, directory)
        (written := Path(directory) / REVISION_FILE).write_bytes(record)
        build_data["force_include"][str(written)] = REVISION_FILE

    def finalize(
        self,
        version: str,
        build_data: (  # ruff: ignore[unused-method-argument] # hatchling's signature
            dict[str, Any]  # simplint: ignore[SMP602] # see above
        ),
        artifact_path: str,
    ) -> None:
        """
        Write the SBOM into the wheel hatchling built, and remove the revision file an sdist build wrote.

        :param version: hatchling's build variant; an editable wheel gets no SBOM, since it carries no code
        :param build_data: hatchling's build data
        :param artifact_path: the built wheel

        """
        if self._remove_revision_file is not None:
            self._remove_revision_file()
        if self.target_name != "wheel" or version == "editable":
            return
        # what a wheel needs loads only when one is built, so an sdist build stays light
        from python_sbom._collect._facts import collect_facts  # ruff: ignore[import-outside-top-level] # see above
        from python_sbom._generate._embed import embed_into  # ruff: ignore[import-outside-top-level] # see above

        root = Path(self.root)
        # content_provider() may be a subclass's override, so its result goes through resolve_provider again, which
        # returns a given instance as is, for the provider's source files to be listed among the build tools
        content, provider_scripts = resolve_provider(self.content_provider(), self._settings, root)
        # a custom hook script shapes the document, as a provider defined in the project does, so the SBOM lists both
        # among the build tools
        own = [PurePosixPath(self.config.get("path", DEFAULT_BUILD_SCRIPT))] if self.PLUGIN_NAME == "custom" else []
        scripts = tuple(dict.fromkeys([*own, *provider_scripts]))
        # hatchling's own fixed time for a reproducible build when SOURCE_DATE_EPOCH is unset, so the SBOM agrees with
        # the zip entries hatchling wrote
        facts = collect_facts(
            root,
            lambda _root: self._revision,
            default_epoch=get_reproducible_timestamp() if self.build_config.reproducible else None,
        )
        embed_into(
            Path(artifact_path), root, settings=self._settings, content=content, build_scripts=scripts, facts=facts
        )

    def content_provider(self) -> ContentProvider:
        """
        Return what the project adds to its SBOM.

        Override it in a hatchling custom build hook to build the provider with what the hook knows; the
        ``content-provider`` option is then ignored.

        :returns: the ``content-provider`` option's provider, or one that adds nothing

        """
        return resolve_provider(None, self._settings, Path(self.root))[0]

    @cached_property
    def _settings(self) -> Settings:
        # hatchling has parsed pyproject.toml already; the hook's own table holds only hatchling's options, so every
        # entry point reads the same [tool.python-sbom]
        if unknown := sorted(self.config.keys() - _HATCHLING_OPTIONS):
            msg = (
                f"the {self.PLUGIN_NAME} hook's table holds {', '.join(unknown)}; move python-sbom's options to"
                " [tool.python-sbom], where python-sbom embed and python-sbom archive read them too"
            )
            raise SbomError(msg)
        return settings_from_table(self.metadata.config.get("tool", {}).get("python-sbom", {}), "[tool.python-sbom]")


__all__ = [
    "SbomBuildHook",
]
