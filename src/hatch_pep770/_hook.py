from __future__ import annotations

import json
import shutil
import tempfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.builders.wheel import WheelBuilder
from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

from ._project import Project, sbom_file_name

if TYPE_CHECKING:
    from ._cyclonedx import Property


class Pep770BuildHook(BuildHookInterface):
    """
    Hatchling build hook that writes a PEP 770 CycloneDX SBOM into the wheel's ``.dist-info/sboms/``.

    Enable it with a ``[tool.hatch.build.hooks.pep770]`` table, or subclass it in a hatchling custom build hook to add
    project-specific detail through :meth:`bundled_wheel_properties`.

    """

    PLUGIN_NAME = "pep770"
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
        metadata = Parser().parsestr(
            builder.config.core_metadata_constructor(self.metadata, extra_dependencies=build_data["dependencies"])
        )
        tag = build_data.get("tag") or (
            builder.get_best_matching_tag() if build_data["infer_tag"] else builder.get_default_tag()
        )
        project = Project.from_table(
            self.config,
            root=Path(self.root),
            where=f"build hook `{self.PLUGIN_NAME}`",
            # a custom build hook script shapes the document, so the SBOM lists it among the build tools
            build_script=PurePosixPath(self.config.get("path", DEFAULT_BUILD_SCRIPT))
            if self.PLUGIN_NAME == "custom"
            else None,
            bundled_wheel_properties=self.bundled_wheel_properties,
        )
        content = json.dumps(project.describe(metadata, f"{builder.artifact_project_id}-{tag}.whl"), indent=2)
        # written outside self.directory, which is also the wheel's output directory, so no stray copy lands next to
        # the built artifacts
        self._sbom_directory = Path(tempfile.mkdtemp(prefix="hatch-pep770-"))
        # bytes, so the line endings do not depend on the build machine's OS
        (sbom := self._sbom_directory / sbom_file_name(metadata)).write_bytes(f"{content}\n".encode())
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


__all__ = [
    "Pep770BuildHook",
]
