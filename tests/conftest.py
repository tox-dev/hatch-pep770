from __future__ import annotations

import base64
import csv
import hashlib
import json
import zipfile
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol

import pytest
from hatchling.builders.wheel import WheelBuilder

if TYPE_CHECKING:
    from collections.abc import Callable

    from hatch_pep770.cyclonedx import Document


class BundleWheel(Protocol):
    def __call__(self, files: dict[str, str], metadata: str = "", name: str = "pip") -> Path: ...


class InstallTool(Protocol):
    def __call__(self, site: Path, name: str, purelib: bool, files: dict[str, bytes]) -> None: ...


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (package := tmp_path / "project" / "src" / "example").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "project" / "LICENSE").write_text("Copyright (c) 2026 Example\n\nMIT terms\n", encoding="utf-8")
    return tmp_path / "project"


@pytest.fixture
def config() -> dict[str, Any]:
    return {
        "project": {
            "name": "Example",
            "version": "1.0",
            "description": "an example",
            "requires-python": ">=3.9",
            "license": "MIT",
            "license-files": ["LICENSE"],
            "maintainers": [{"name": "Maintainer", "email": "maintainer@example.com"}],
            "keywords": ["sample"],
            "classifiers": ["Programming Language :: Python :: 3"],
            "dependencies": ["packaging>=24", "tomli>=2; python_version<'3.11'"],
            "urls": {"Changelog": "https://example.com/changelog", "Source": "https://github.com/example/example"},
        },
        "tool": {
            "hatch": {
                "build": {
                    "targets": {"wheel": {"packages": ["src/example"]}},
                    "hooks": {"pep770": {}},
                }
            }
        },
    }


@pytest.fixture
def build_sbom(root: Path) -> Callable[[dict[str, Any]], str]:
    # drives the hook through hatchling's own wheel builder, also on hatchling releases that predate `sbom_files`
    def build(config: dict[str, Any]) -> str:
        builder: Final[WheelBuilder] = WheelBuilder(str(root), config=config)
        build_data: Final[dict[str, Any]] = {**builder.get_default_build_data(), "sbom_files": []}
        (hook,) = builder.get_build_hooks(str(root / "dist")).values()
        hook.initialize("standard", build_data)
        content = Path(build_data["sbom_files"][0]).read_text(encoding="utf-8")
        hook.finalize("standard", build_data, str(root / "dist" / "example.whl"))
        return content

    return build


@pytest.fixture
def build_wheel(root: Path, tmp_path: Path) -> Callable[[dict[str, Any], str], Path]:
    def build(config: dict[str, Any], out: str) -> Path:
        (artifact,) = WheelBuilder(str(root), config=config).build(directory=str(tmp_path / out), versions=["standard"])
        return Path(artifact)

    return build


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
def install_tool() -> InstallTool:
    def install(site: Path, name: str, purelib: bool, files: dict[str, bytes]) -> None:
        record: Final[StringIO] = StringIO(newline="")
        for path, content in files.items():
            (target := site / path).parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
            csv.writer(record).writerow((path, f"sha256={digest}", len(content)))
        (dist_info := site / f"{name}-1.0.dist-info").mkdir(exist_ok=True)
        (dist_info / "METADATA").write_text(f"Metadata-Version: 2.4\nName: {name}\nVersion: 1.0\n", encoding="utf-8")
        (dist_info / "WHEEL").write_text(
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: {str(purelib).lower()}\n", encoding="utf-8"
        )
        (dist_info / "RECORD").write_bytes(record.getvalue().encode())

    return install


@pytest.fixture
def sbom_document(build_sbom: Callable[[dict[str, Any]], str], config: dict[str, Any]) -> Document:
    return json.loads(build_sbom(config))
