from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from python_sbom import BundledWheelInfo, ContentProvider
from python_sbom.hatch import SbomBuildHook

if TYPE_CHECKING:
    from python_sbom import BundledWheel, Settings


def get_build_hook() -> type[SeedSbomHook]:
    # the module also sees the base class, so hatchling needs to be told which subclass to load
    return SeedSbomHook


class SeedSbomHook(SbomBuildHook):
    def content_provider(
        self,
        settings: Settings,  # ruff: ignore[unused-method-argument] # the base class's signature
    ) -> tuple[ContentProvider, tuple[PurePosixPath, ...]]:
        # no script to add: the SBOM already lists this one, the hook, among the build tools
        return BundleSupport(Path(self.root), self.metadata.name), ()


class BundleSupport(ContentProvider):
    def __init__(self, root: Path, project: str) -> None:
        self._root = root
        self._project = project

    def bundled_wheel(self, wheel: BundledWheel) -> BundledWheelInfo:
        # the BUNDLE_SUPPORT table next to the wheels decides which Python versions receive each one; it is read by
        # name, without importing the package
        path = PurePosixPath(wheel.path)
        module = ast.parse((self._root / str(path.parent) / "__init__.py").read_text(encoding="utf-8"))
        support: dict[str, dict[str, str]] = ast.literal_eval(
            next(
                node.value
                for node in module.body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "BUNDLE_SUPPORT" for target in node.targets)
            )
        )
        return BundledWheelInfo(
            properties=[
                {"name": f"{self._project}:seeded-for-python", "value": python}
                for python, wheels in support.items()
                if path.name in wheels.values()
            ],
            supplier=None,
        )
