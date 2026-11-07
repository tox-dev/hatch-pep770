from __future__ import annotations

import tempfile
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.builders.utils import get_reproducible_timestamp
from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

from python_sbom._collect._content import load_content_provider, provider_script
from python_sbom._collect._facts import REVISION_FILE, collect_facts, default_revision
from python_sbom._collect._settings import settings_from_table
from python_sbom._collect._source import wheel_request
from python_sbom._errors import SettingsError
from python_sbom._generate._embed import embed_into

if TYPE_CHECKING:
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

    def initialize(
        self,
        version: str,  # ruff: ignore[unused-method-argument] # hatchling's signature
        build_data: dict[str, Any],  # simplint: ignore[SMP602] # hatchling's signature
    ) -> None:
        """
        Record the source revision in an sdist.

        :param version: hatchling's build variant
        :param build_data: hatchling's build data, which receives the revision file

        """
        # a dirty checkout has no commit that reproduces the sdist, so a wheel built from it names none
        if self.target_name != "sdist" or (revision := default_revision(Path(self.root))) is None or revision.dirty:
            return
        # outside the project, so the build leaves nothing behind in it; bytes, so the sdist holds the same LF line on
        # every OS
        written = Path(tempfile.mkdtemp()) / REVISION_FILE
        written.write_bytes(f"node: {revision.commit}\n".encode())
        build_data["force_include"][str(written)] = REVISION_FILE

    def finalize(
        self,
        version: str,
        build_data: dict[str, Any],  # ruff: ignore[unused-method-argument] # simplint: ignore[SMP602] # hatchling's signature
        artifact_path: str,
    ) -> None:
        """
        Write the SBOM into the wheel hatchling built.

        :param version: hatchling's build variant; an editable wheel gets no SBOM, since it carries no code
        :param build_data: hatchling's build data
        :param artifact_path: the built wheel

        """
        if self.target_name != "wheel" or version == "editable":
            return
        root = Path(self.root)
        content = self.content_provider()
        # a custom hook script shapes the document, as a provider defined in the project does, so the SBOM lists both
        # among the build tools
        own = [PurePosixPath(self.config.get("path", DEFAULT_BUILD_SCRIPT))] if self.PLUGIN_NAME == "custom" else []
        scripts = tuple(dict.fromkeys([*own, *filter(None, [provider_script(content, root)])]))
        # hatchling's own fixed time for a reproducible build when SOURCE_DATE_EPOCH is unset, so the SBOM agrees with
        # the zip entries hatchling wrote
        facts = collect_facts(
            root,
            default_revision,
            default_epoch=get_reproducible_timestamp() if self.build_config.reproducible else None,
        )
        wheel = Path(artifact_path)
        embed_into(wheel, wheel_request(wheel, root, self._settings, scripts), content, facts)

    def content_provider(self) -> ContentProvider:
        """
        Return what the project adds to its SBOM.

        Override it in a hatchling custom build hook to build the provider with what the hook knows; the
        ``content-provider`` option is then ignored.

        :returns: the ``content-provider`` option's provider, or one that adds nothing

        """
        return load_content_provider(self._settings.content_provider, Path(self.root))

    @cached_property
    def _settings(self) -> Settings:
        # hatchling has parsed pyproject.toml already; the hook's own table holds only hatchling's options, so every
        # entry point reads the same [tool.python-sbom]
        if unknown := sorted(self.config.keys() - _HATCHLING_OPTIONS):
            msg = (
                f"the {self.PLUGIN_NAME} hook's table holds {', '.join(unknown)}; move python-sbom's options to"
                " [tool.python-sbom], where python-sbom embed and python-sbom archive read them too"
            )
            raise SettingsError(msg)
        return settings_from_table(self.metadata.config.get("tool", {}).get("python-sbom", {}), "[tool.python-sbom]")


__all__ = [
    "SbomBuildHook",
]
