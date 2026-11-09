from __future__ import annotations

import json
import tarfile
import zipfile
from typing import TYPE_CHECKING, Final

import pytest
from pdm.backend import build_editable, build_sdist, build_wheel

from python_sbom._validate._artifact import validate

if TYPE_CHECKING:
    from pathlib import Path

    from tests.conftest import Git

_SBOM: Final[str] = "example-1.0.dist-info/sboms/example.cdx.json"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return write_project(tmp_path / "project", "\n[tool.python-sbom]\n", monkeypatch)


def write_project(root: Path, tables: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    (root / "src" / "example").mkdir(parents=True, exist_ok=True)
    (root / "src" / "example" / "__init__.py").write_text("", encoding="utf-8")
    (root / "LICENSE").write_text("Copyright (c) 2026 Example\n\nMIT terms\n", encoding="utf-8")
    project = """\
[build-system]
build-backend = "pdm.backend"
requires = ["pdm-backend", "python-sbom"]

[project]
name = "example"
version = "1.0"
description = "an example"
license = "MIT"
license-files = ["LICENSE"]
urls.Source = "https://github.com/example/example"
"""
    (root / "pyproject.toml").write_text(f"{project}{tables}", encoding="utf-8")
    # a frontend creates the output directory before it calls the backend
    (root / "dist").mkdir(exist_ok=True)
    monkeypatch.chdir(root)
    return root


def test_wheel_carries_valid_sbom(project: Path) -> None:
    assert validate(project / "dist" / build_wheel(str(project / "dist")), frozenset({"MIT"})) == []


def test_reproducible_build_uses_pdm_backend_time(project: Path) -> None:
    wheel = project / "dist" / build_wheel(str(project / "dist"))
    assert json.loads(zipfile.ZipFile(wheel).read(_SBOM))["metadata"]["timestamp"] == "2016-01-01T00:00:00+00:00"


def test_project_without_table_has_no_sbom(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = write_project(tmp_path / "project", "", monkeypatch)
    assert sboms(root / "dist" / build_wheel(str(root / "dist"))) == []


def sboms(wheel: Path) -> list[str]:
    return [name for name in zipfile.ZipFile(wheel).namelist() if "/sboms/" in name]


def test_editable_wheel_has_no_sbom(project: Path) -> None:
    assert sboms(project / "dist" / build_editable(str(project / "dist"))) == []


@pytest.fixture
def checkout(tmp_path: Path, git: Git, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = write_project(tmp_path / "checkout", "\n[tool.python-sbom]\n", monkeypatch)
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "--message", "first")
    return root


def test_sdist_records_clean_revision(checkout: Path, git: Git) -> None:
    sdist = checkout / "dist" / build_sdist(str(checkout / "dist"))
    assert revision_of(sdist) == f"node: {git('rev-parse', 'HEAD')}\n".encode()


def revision_of(sdist: Path) -> bytes | None:
    with tarfile.open(sdist) as archive:
        if "example-1.0/.python-sbom-revision" not in archive.getnames():
            return None
        handle = archive.extractfile("example-1.0/.python-sbom-revision")
        assert handle is not None
        return handle.read()


def test_sdist_of_dirty_checkout_records_no_revision(checkout: Path) -> None:
    (checkout / "LICENSE").write_text("changed\n", encoding="utf-8")
    assert revision_of(checkout / "dist" / build_sdist(str(checkout / "dist"))) is None


def test_wheel_from_sdist_names_its_commit(checkout: Path, git: Git, tmp_path: Path) -> None:
    with tarfile.open(checkout / "dist" / build_sdist(str(checkout / "dist"))) as archive:
        archive.extractall(tmp_path / "unpacked", filter="data")
    wheel = checkout / "dist" / build_wheel(str(checkout / "dist"))
    unpacked = tmp_path / "unpacked" / "example-1.0"
    with pytest.MonkeyPatch.context() as patch:
        patch.chdir(unpacked)
        from_sdist = unpacked / "dist" / build_wheel(str(unpacked / "dist"))
    component = json.loads(zipfile.ZipFile(from_sdist).read(_SBOM))["metadata"]["component"]
    assert git("rev-parse", "HEAD") in json.dumps(component)
    assert wheel.name == from_sdist.name
