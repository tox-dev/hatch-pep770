from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

import pytest
from hatchling.builders.sdist import SdistBuilder
from hatchling.builders.wheel import WheelBuilder

if TYPE_CHECKING:
    from tests.conftest import WriteWheel


class BuildWheel(Protocol):
    def __call__(self, root: Path, *, version: str = "standard", target: str = "wheel") -> Path: ...


_SEEDER: Final[Path] = Path(__file__).parent.parent / "_seeder"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    project = """\
[project]
name = "Example"
version = "1.0"
description = "an example"
license = "MIT"
license-files = ["LICENSE"]
dependencies = ["packaging>=24"]
urls.Source = "https://github.com/example/example"

[tool.hatch.build.targets.wheel]
packages = ["src/example"]
"""
    (package := tmp_path / "project" / "src" / "example").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "project" / "LICENSE").write_text("Copyright (c) 2026 Example\n\nMIT terms\n", encoding="utf-8")
    (tmp_path / "project" / "pyproject.toml").write_text(
        f"{project}\n[tool.hatch.build.hooks.python-sbom]\n", encoding="utf-8"
    )
    return tmp_path / "project"


@pytest.fixture
def build_wheel(tmp_path: Path) -> BuildWheel:
    def build(root: Path, *, version: str = "standard", target: str = "wheel") -> Path:
        builder = (WheelBuilder if target == "wheel" else SdistBuilder)(str(root))
        (artifact,) = builder.build(directory=str(tmp_path / "dist"), versions=[version])
        return Path(artifact)

    return build


@pytest.fixture
def seeder(tmp_path: Path, write_wheel: WriteWheel) -> Path:
    # a copy, so the build leaves nothing in the source tree; the hook script stays the checked-in one, so coverage
    # measures it
    shutil.copytree(_SEEDER, target := tmp_path / "seeder", ignore=shutil.ignore_patterns("hatch_build.py"))
    pyproject = target / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            "build.hooks.custom.supplier",
            f'build.hooks.custom.path = "{(_SEEDER / "hatch_build.py").as_posix()}"\nbuild.hooks.custom.supplier',
        ),
        encoding="utf-8",
    )
    # the pip wheel a seeder bundles, built here so the repository holds no binaries
    write_wheel(
        target / "src" / "seeder" / "embed" / "pip-1.0-py3-none-any.whl",
        {
            "pip/__init__.py": b"",
            "pip/_vendor/vendor.txt": b"urllib3==1.26.4\n",
            "pip-1.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: pip\nVersion: 1.0\nLicense-Expression: MIT\n",
            "pip-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        },
    )
    return target
