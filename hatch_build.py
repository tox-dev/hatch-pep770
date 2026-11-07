"""Write python-sbom's own SBOM into its wheel with the hook the package ships."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class SelfSbomHook(BuildHookInterface):  # simplint: ignore[SMP409] # hatchling loads it from this script
    def finalize(
        self,
        version: str,
        build_data: dict[str, Any],  # simplint: ignore[SMP602] # hatchling's signature
        artifact_path: str,
    ) -> None:
        # python-sbom cannot be a build requirement of itself, so its hook comes from this source tree; by now the vcs
        # hook has written the version module the package imports
        sys.path.insert(0, str(Path(self.root) / "src"))
        from python_sbom.hatch import SbomBuildHook  # ruff: ignore[import-outside-top-level] # see above

        hook = SbomBuildHook(
            self.root, self.config, self.build_config, self.metadata, self.directory, self.target_name, self.app
        )
        # as hatchling names a custom hook, so the SBOM lists this script among the build tools
        hook.PLUGIN_NAME = self.PLUGIN_NAME
        hook.finalize(version, build_data, artifact_path)
