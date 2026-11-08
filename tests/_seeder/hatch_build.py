from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from python_sbom import BundledWheelInfo, ContentProvider
from python_sbom.hatch import SbomBuildHook

if TYPE_CHECKING:
    from pathlib import PurePosixPath

    from python_sbom import ProviderContext


def get_build_hook() -> type[SeedSbomHook]:
    # the module also sees the base class, so hatchling needs to be told which subclass to load
    return SeedSbomHook


class SeedSbomHook(SbomBuildHook):
    def content_provider(self) -> ContentProvider:  # ruff: ignore[no-self-use] # overrides the hook's factory
        return BundleSupport("BUNDLE_SUPPORT")


class BundleSupport(ContentProvider):
    def __init__(self, table: str) -> None:
        self._table = table

    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
        # the table next to the wheels decides which Python versions receive each one; it is read by name, without
        # importing the package
        module = ast.parse(context.read(wheel.parent / "__init__.py").decode("utf-8"))
        support: dict[str, dict[str, str]] = ast.literal_eval(
            next(
                node.value
                for node in module.body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == self._table for target in node.targets)
            )
        )
        return BundledWheelInfo(
            properties=[
                {"name": f"{context.identity.property_prefix}:seeded-for-python", "value": python}
                for python, wheels in support.items()
                if wheel.name in wheels.values()
            ],
            # the seeder bundles only its own supplier's wheels
            supplier=context.settings.supplier,
        )
