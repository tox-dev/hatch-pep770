from __future__ import annotations

import json
import zipfile
from typing import TYPE_CHECKING

from python_sbom import BundledWheelInfo, ContentProvider, ProviderContext
from python_sbom._generate._embed import embed_sbom

if TYPE_CHECKING:
    from pathlib import Path, PurePosixPath

    from conftest import WriteWheel


def test_bundled_wheel_named_by_its_path_inside_the_wheel(tmp_path: Path, write_wheel: WriteWheel) -> None:
    (root := tmp_path / "project").mkdir()
    (root / "pyproject.toml").write_text("[tool.python-sbom]\nbundled-wheels = ['src/pkg/wheels/*.whl']\n")
    bundled = write_wheel(
        root / "src" / "pkg" / "wheels" / "pip-1.0-py3-none-any.whl",
        {"pip/__init__.py": b"", "pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\nLicense-Expression: MIT\n"},
    )
    wheel = write_wheel(
        tmp_path / "dist" / "pkg-1.0-py3-none-any.whl",
        {
            "pkg/wheels/pip-1.0-py3-none-any.whl": bundled.read_bytes(),
            "pkg/wheels/table.txt": b"3.15\n",
            "pkg-1.0.dist-info/METADATA": b"Name: pkg\nVersion: 1.0\n",
        },
    )
    written = embed_sbom(wheel, root, content=Table("table.txt"), build_env=[str(root)])
    (pip,) = json.loads(zipfile.ZipFile(wheel).read(written))["components"]
    assert (pip["bom-ref"], pip["properties"][:2]) == (
        "bundled:pkg/wheels/pip-1.0-py3-none-any.whl",
        [
            {"name": "pkg:bundled-wheel", "value": "pkg/wheels/pip-1.0-py3-none-any.whl"},
            {"name": "pkg:table", "value": "3.15"},
        ],
    )


class Table(ContentProvider):
    def __init__(self, name: str) -> None:
        self._name = name

    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
        # the table sits next to the wheel inside the built wheel
        value = context.read(wheel.parent / self._name).decode().strip()
        return BundledWheelInfo(properties=[{"name": f"{context.identity.property_prefix}:table", "value": value}])
