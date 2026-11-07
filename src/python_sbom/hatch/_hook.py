from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.builders.utils import get_reproducible_timestamp
from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

from python_sbom._collect._facts import collect_facts, default_revision
from python_sbom._collect._settings import settings_from_table
from python_sbom._collect._source import read_source_tree
from python_sbom._generate._backend import BuiltWheel
from python_sbom._generate._content import ContentProvider, load_content_provider
from python_sbom._generate._pipeline import build_sbom
from python_sbom._wheel._archive import embed_sbom

if TYPE_CHECKING:
    from python_sbom._generate._backend import Backend
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
    whatever other hooks changed. Options come from ``[tool.python-sbom]``, overridden by the hook's own table.

    :cvar PLUGIN_NAME: the hook's name in ``[tool.hatch.build.hooks]``

    """

    PLUGIN_NAME = "python-sbom"

    def finalize(
        self,
        version: str,
        build_data: dict[str, Any],  # ruff: ignore[unused-method-argument] # simplint: ignore[SMP602] # hatchling's signature
        artifact_path: str,
    ) -> None:
        """
        Write the SBOM into the wheel hatchling built.

        :param version: hatchling's build variant; an editable wheel gets no SBOM, since it carries no code
        :param build_data: unused
        :param artifact_path: the built wheel

        """
        if self.target_name != "wheel" or version == "editable":
            return
        root = Path(self.root)
        # hatchling has parsed pyproject.toml already
        settings = settings_from_table(
            {
                **self.metadata.config.get("tool", {}).get("python-sbom", {}),
                **{key: value for key, value in self.config.items() if key not in _HATCHLING_OPTIONS},
            },
            f"[tool.python-sbom] or the {self.PLUGIN_NAME} hook's table",
        )
        content, provider_scripts = self.content_provider(settings)
        # a custom hook script shapes the document, so the SBOM lists it among the build tools
        own_script = (
            (PurePosixPath(self.config.get("path", DEFAULT_BUILD_SCRIPT)),) if self.PLUGIN_NAME == "custom" else ()
        )
        request = self.backend(Path(artifact_path), settings, (*own_script, *provider_scripts)).request()
        # hatchling's own fixed time for a reproducible build when SOURCE_DATE_EPOCH is unset, so the SBOM agrees with
        # the zip entries hatchling wrote
        facts = collect_facts(
            root, default_revision, None, get_reproducible_timestamp() if self.build_config.reproducible else None
        )
        sbom = build_sbom(request, read_source_tree(request), facts, content)
        embed_sbom(Path(artifact_path), sbom.file_name, sbom.content, facts.epoch)

    def content_provider(self, settings: Settings) -> tuple[ContentProvider, tuple[PurePosixPath, ...]]:
        """
        Return what the project adds to its SBOM; override it in a custom build hook to supply a provider directly.

        :param settings: the project's options
        :returns: the provider and the scripts that define it; by default the ``content-provider`` option's, or none

        """
        if settings.content_provider is None:
            return ContentProvider(), ()
        provider, script = load_content_provider(settings.content_provider, Path(self.root))
        return provider, () if script is None else (script,)

    def backend(self, wheel: Path, settings: Settings, build_scripts: tuple[PurePosixPath, ...]) -> Backend:
        """
        Return the backend that describes the built wheel.

        :param wheel: the wheel hatchling built
        :param settings: the project's options
        :param build_scripts: the scripts that shape the document
        :returns: a :class:`~python_sbom.BuiltWheel` by default

        """
        return BuiltWheel(wheel=wheel, root=Path(self.root), settings=settings, build_scripts=build_scripts)


__all__ = [
    "SbomBuildHook",
]
