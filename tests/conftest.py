from __future__ import annotations

import base64
import csv
import hashlib
import json
import shutil
import zipfile
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

import pytest
from hatchling.builders.wheel import WheelBuilder

from python_sbom import Project

if TYPE_CHECKING:
    from python_sbom import Document

_PROJECT: Final[str] = """\
[project]
name = "Example"
version = "1.0"
description = "an example"
requires-python = ">=3.11"
license = "MIT"
license-files = ["LICENSE"]
maintainers = [{ name = "Maintainer", email = "maintainer@example.com" }]
keywords = ["sample", "demo"]
classifiers = ["Programming Language :: Python :: 3"]
dependencies = ["packaging>=24", "tomli>=2; python_version<'3.11'"]
optional-dependencies.cli = ["click>=8"]
urls.Changelog = "https://example.com/changelog"
urls.Source = "https://github.com/example/example"
"""
HOOK: Final[str] = "[tool.hatch.build.hooks.python-sbom]\n"
BUNDLED: Final[str] = 'bundled-wheels = ["src/example/wheels/*.whl"]\n'
_SEEDER: Final[Path] = Path(__file__).parent / "seeder"


class WriteProject(Protocol):
    def __call__(self, *, hook: str = HOOK, project: str = _PROJECT) -> Path: ...


class BundleWheel(Protocol):
    def __call__(self, files: dict[str, str], metadata: str = "", name: str = "pip") -> Path: ...


class MakeWheel(Protocol):
    def __call__(self, metadata: str) -> Path: ...


class InstallTool(Protocol):
    def __call__(self, site: Path, name: str, purelib: bool, files: dict[str, bytes]) -> None: ...


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # an exported SOURCE_DATE_EPOCH would move every timestamp the tests expect
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    (package := tmp_path / "project" / "src" / "example").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "project" / "LICENSE").write_text("Copyright (c) 2026 Example\n\nMIT terms\n", encoding="utf-8")
    return tmp_path / "project"


@pytest.fixture
def write_project(root: Path) -> WriteProject:
    def write(*, hook: str = HOOK, project: str = _PROJECT) -> Path:
        targets = '[tool.hatch.build.targets.wheel]\npackages = ["src/example"]\n'
        (root / "pyproject.toml").write_text(f"{project}\n{targets}\n{hook}", encoding="utf-8")
        return root

    return write


@pytest.fixture
def build_sbom(write_project: WriteProject) -> BuildSbom:
    def build(*, hook: str = HOOK, project: str = _PROJECT) -> Document:
        return build_hook_sbom(write_project(hook=hook, project=project))

    return build


class BuildSbom(Protocol):
    def __call__(self, *, hook: str = HOOK, project: str = _PROJECT) -> Document: ...


def build_hook_sbom(root: Path) -> Document:
    builder: Final[WheelBuilder] = WheelBuilder(str(root))
    build_data = builder.get_default_build_data()
    (hook,) = builder.get_build_hooks(str(root / "dist")).values()
    hook.initialize("standard", build_data)
    (sbom,) = build_data["sbom_files"]
    document: Final[Document] = json.loads(Path(sbom).read_text(encoding="utf-8"))
    hook.finalize("standard", build_data, str(root / "dist" / "example.whl"))
    return document


@pytest.fixture
def seeder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    # a copy, so the build cannot leave files in the source tree; the build script it loads stays the checked-in one
    shutil.copytree(_SEEDER, target := tmp_path / "seeder", ignore=shutil.ignore_patterns("hatch_build.py"))
    pyproject = (target / "pyproject.toml").read_text(encoding="utf-8")
    script = (_SEEDER / "hatch_build.py").as_posix()
    (target / "pyproject.toml").write_text(
        pyproject.replace(
            "build.hooks.custom.supplier", f'build.hooks.custom.path = "{script}"\nbuild.hooks.custom.supplier'
        ),
        encoding="utf-8",
    )
    write_seed_wheel(target / "src" / "seeder" / "embed")
    return target


def write_seed_wheel(directory: Path) -> Path:
    # the pip wheel a seeder bundles, built here rather than committed so the repository holds no binaries
    files: Final[dict[str, bytes]] = {
        "pip/__init__.py": b"",
        "pip/_vendor/vendor.txt": b"urllib3==1.26.4\n",
        "pip-1.0.dist-info/METADATA": (
            b"Metadata-Version: 2.4\nName: pip\nVersion: 1.0\nLicense-Expression: MIT\n"
            b"Project-URL: Source, https://github.com/example/pip\n"
        ),
        "pip-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = "".join(f"{name},{digest(content)},{len(content)}\n" for name, content in files.items())
    files["pip-1.0.dist-info/RECORD"] = f"{record}pip-1.0.dist-info/RECORD,,\n".encode()
    with zipfile.ZipFile(wheel := directory / "pip-1.0-py3-none-any.whl", "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(zipfile.ZipInfo(name, (2020, 2, 2, 0, 0, 0)), content, zipfile.ZIP_DEFLATED)
    return wheel


@pytest.fixture
def bundle_wheel(root: Path) -> BundleWheel:
    def bundle(files: dict[str, str], metadata: str = "", name: str = "pip") -> Path:
        (wheels := root / "src" / "example" / "wheels").mkdir(parents=True, exist_ok=True)
        record: Final[StringIO] = StringIO(newline="")
        csv.writer(record).writerows([
            (f"{name}/example.py", "sha256=ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", "3"),
            (f"{name}-1.0.dist-info/RECORD", "", ""),
        ])
        with zipfile.ZipFile(wheel := wheels / f"{name}-1.0-py3-none-any.whl", "w") as archive:
            for path, content in files.items():
                archive.writestr(zipfile.ZipInfo(path), content)
            archive.writestr(
                zipfile.ZipInfo(f"{name}-1.0.dist-info/METADATA"),
                f"Metadata-Version: 2.4\nName: {name}\nVersion: 1.0\n{metadata}",
            )
            archive.writestr(zipfile.ZipInfo(f"{name}-1.0.dist-info/RECORD"), record.getvalue())
            archive.writestr(zipfile.ZipInfo(f"{name}/example.py"), b"abc")
        return wheel

    return bundle


@pytest.fixture
def make_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MakeWheel:
    # the layout another build backend, such as meson-python, writes: module first, .dist-info last, RECORD at the end
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    def make(metadata: str) -> Path:
        files: Final[dict[str, bytes]] = {
            "native/__init__.py": b"",
            "native-1.0.dist-info/METADATA": f"Metadata-Version: 2.4\nName: native\nVersion: 1.0\n{metadata}".encode(),
            "native-1.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nGenerator: meson\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
            ),
        }
        record = "".join(f"{name},{digest(content)},{len(content)}\n" for name, content in files.items())
        (dist := tmp_path / "dist").mkdir(exist_ok=True)
        with zipfile.ZipFile(wheel := dist / "native-1.0-py3-none-any.whl", "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in {
                **files,
                "native-1.0.dist-info/RECORD": f"{record}native-1.0.dist-info/RECORD,,\n".encode(),
            }.items():
                info = zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, content)
        return wheel

    return make


def digest(content: bytes) -> str:
    return f"sha256={base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()}"


@pytest.fixture
def install_tool() -> InstallTool:
    def install(site: Path, name: str, purelib: bool, files: dict[str, bytes]) -> None:
        record: Final[StringIO] = StringIO(newline="")
        csv.writer(record).writerows((path, digest(content), len(content)) for path, content in files.items())
        for path, content in files.items():
            (target := site / path).parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        (dist_info := site / f"{name}-1.0.dist-info").mkdir(exist_ok=True)
        (dist_info / "METADATA").write_text(f"Metadata-Version: 2.4\nName: {name}\nVersion: 1.0\n", encoding="utf-8")
        (dist_info / "WHEEL").write_text(
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: {str(purelib).lower()}\n", encoding="utf-8"
        )
        (dist_info / "RECORD").write_bytes(record.getvalue().encode())

    return install


@pytest.fixture
def plain_project(tmp_path: Path) -> Project:
    return Project.from_table({}, root=tmp_path, where="[tool.python-sbom]")
