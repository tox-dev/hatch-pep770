from __future__ import annotations

import shutil
import tempfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.builders.wheel import WheelBuilder
from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

from python_sbom._backend import Backend
from python_sbom._collect._facts import BuildFacts, git_revision
from python_sbom._collect._settings import Settings
from python_sbom._extension import ContentProvider

if TYPE_CHECKING:
    from email.message import Message

    from python_sbom._model._types import Property


class SbomBuildHook(BuildHookInterface, ContentProvider):
    """
    Hatchling build hook that writes a CycloneDX SBOM into the wheel's ``.dist-info/sboms/``, as PEP 770 describes.

    Enable it with a ``[tool.hatch.build.hooks.python-sbom]`` table, or subclass it in a hatchling custom build hook to
    add project-specific detail through :meth:`bundled_wheel_properties`.

    """

    PLUGIN_NAME = "python-sbom"
    _sbom_directory: Path | None = None

    def initialize(
        self,
        version: str,  # ruff: ignore[unused-method-argument]  # hatchling's signature
        build_data: dict[str, Any],  # simplint: ignore[SMP602]  # hatchling API
    ) -> None:
        """
        Write the SBOM and register it with the wheel build.

        :param version: hatchling's build variant name, such as ``standard``
        :param build_data: the build data, whose ``sbom_files`` receives the SBOM

        """
        if not isinstance(builder := self.build_config.builder, WheelBuilder):
            return
        tag = build_data.get("tag") or (
            builder.get_best_matching_tag() if build_data["infer_tag"] else builder.get_default_tag()
        )
        backend = _HatchBackend(
            hook=self,
            metadata=builder.config.core_metadata_constructor(
                self.metadata, extra_dependencies=build_data["dependencies"]
            ),
            wheel_name=f"{builder.artifact_project_id}-{tag}.whl",
        )
        name, content = backend.sbom(BuildFacts.collect(backend.root, git_revision))
        # written outside self.directory, which is also the wheel's output directory, so no stray copy lands next to
        # the built artifacts
        self._sbom_directory = Path(tempfile.mkdtemp(prefix="python-sbom-"))
        (sbom := self._sbom_directory / name).write_bytes(content)
        build_data["sbom_files"].append(str(sbom))

    def bundled_wheel_properties(  # ruff: ignore[no-self-use]  # subclasses override it
        self,
        wheel: Path,  # ruff: ignore[unused-method-argument]  # subclasses use it
    ) -> list[Property]:
        """
        Return extra properties for a wheel the project bundles as a data file.

        Override it to say what the project does with the wheel, for example which Python versions receive it. The
        properties follow ``<project>:bundled-wheel`` and precede the ones taken from the wheel's metadata.

        :param wheel: the bundled wheel, an absolute path under the project root
        :returns: the properties to add; the default adds none

        """
        return []

    def finalize(
        self,
        version: str,  # ruff: ignore[unused-method-argument]  # hatchling's signature
        build_data: dict[str, Any],  # ruff: ignore[unused-method-argument]  # simplint: ignore[SMP602]  # hatchling API
        artifact_path: str,  # ruff: ignore[unused-method-argument]  # hatchling's signature
    ) -> None:
        """
        Remove the SBOM's temporary directory once hatchling copied the file into the wheel.

        :param version: hatchling's build variant name
        :param build_data: the build data
        :param artifact_path: the built wheel

        """
        if self._sbom_directory is not None:
            shutil.rmtree(self._sbom_directory)
            self._sbom_directory = None


class _HatchBackend(Backend):
    def __init__(self, *, hook: SbomBuildHook, metadata: str, wheel_name: str) -> None:
        self._hook = hook
        self._metadata = metadata
        self._wheel_name = wheel_name

    @property
    def root(self) -> Path:
        return Path(self._hook.root)

    @property
    def settings(self) -> Settings:
        return Settings.from_table(self._hook.config, f"build hook `{self._hook.PLUGIN_NAME}`")

    def metadata(self) -> Message:
        return Parser().parsestr(self._metadata)

    def wheel_name(self) -> str:
        return self._wheel_name

    def build_script(self) -> PurePosixPath | None:
        # a custom build hook script shapes the document, so the SBOM lists it among the build tools
        if self._hook.PLUGIN_NAME != "custom":
            return None
        return PurePosixPath(self._hook.config.get("path", DEFAULT_BUILD_SCRIPT))

    def bundled_wheel_properties(self, wheel: Path) -> list[Property]:
        return self._hook.bundled_wheel_properties(wheel)


__all__ = [
    "SbomBuildHook",
]
