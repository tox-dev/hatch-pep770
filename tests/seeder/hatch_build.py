from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

from hatch_pep770 import Pep770BuildHook

if TYPE_CHECKING:
    from hatch_pep770 import Property


def get_build_hook() -> type[SeederBuildHook]:
    # the module also sees the base class, so hatchling needs to be told which subclass to load
    return SeederBuildHook


class SeederBuildHook(Pep770BuildHook):
    def bundled_wheel_properties(self, wheel: Path) -> list[Property]:
        # the table that decides which Python versions receive each wheel, read without importing the package
        tree = ast.parse((Path(self.root) / "src" / "seeder" / "embed" / "bundle.py").read_text(encoding="utf-8"))
        support: dict[str, dict[str, str]] = ast.literal_eval(
            next(node.value for node in tree.body if isinstance(node, ast.AnnAssign) and node.value is not None)
        )
        return [
            {"name": "seeder:seeded-for-python", "value": python}
            for python, wheels in support.items()
            if wheel.name in wheels.values()
        ]
