from __future__ import annotations

import json
import tarfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import flit_core.buildapi
import pytest

from python_sbom import backend
from python_sbom._errors import SbomError
from python_sbom._validate._artifact import validate

if TYPE_CHECKING:
    from collections.abc import Mapping

    from tests.conftest import Git

# an in-tree backend that defines only the two hooks PEP 517 requires, and an sdist holding the revision file already
_MINIMAL: Final[str] = """\
import flit_core.buildapi as flit

build_wheel = flit.build_wheel


def build_sdist(sdist_directory, config_settings=None):
    return flit.build_sdist(sdist_directory, config_settings)
"""


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return write_project(tmp_path / "project", "build-backend = 'flit_core.buildapi'\n", monkeypatch)


def write_project(root: Path, options: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    (root / "example").mkdir(parents=True, exist_ok=True)
    (root / "example" / "__init__.py").write_text("", encoding="utf-8")
    (root / "LICENSE").write_text("Copyright (c) 2026 Example\n\nMIT terms\n", encoding="utf-8")
    project = """\
[build-system]
build-backend = "python_sbom.backend"
requires = ["flit-core>=3.12", "python-sbom"]

[project]
name = "example"
version = "1.0"
description = "an example"
license = "MIT"
license-files = ["LICENSE"]
urls.Source = "https://github.com/example/example"

[tool.python-sbom]
"""
    (root / "pyproject.toml").write_text(f"{project}{options}", encoding="utf-8")
    # PEP 517 runs every hook from the project directory, where an in-tree backend is importable too
    # a frontend creates the output directory before it calls the backend
    (root / "dist").mkdir(exist_ok=True)
    monkeypatch.chdir(root)
    monkeypatch.syspath_prepend(str(root))
    return root


def test_wheel_carries_valid_sbom(project: Path) -> None:
    wheel = project / "dist" / backend.build_wheel(str(project / "dist"))
    assert validate(wheel, frozenset({"MIT"})) == []


def test_sbom_records_the_build_environment(project: Path) -> None:
    wheel = project / "dist" / backend.build_wheel(str(project / "dist"))
    tools = json.loads(zipfile.ZipFile(wheel).read("example-1.0.dist-info/sboms/example.cdx.json"))["metadata"][
        "tools"
    ]["components"]
    assert "flit_core" in {tool["name"] for tool in tools}


@pytest.mark.usefixtures("project")
def test_optional_hook_comes_from_the_wrapped_backend() -> None:
    assert backend.prepare_metadata_for_build_wheel is flit_core.buildapi.prepare_metadata_for_build_wheel


def test_optional_hook_the_backend_lacks_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / f"{tmp_path.name}.py").write_text(_MINIMAL, encoding="utf-8")
    write_project(tmp_path / "project", f"build-backend = '{tmp_path.name}'\n", monkeypatch)
    assert not hasattr(backend, "prepare_metadata_for_build_wheel")


@pytest.mark.usefixtures("project")
def test_unknown_attribute_is_missing() -> None:
    with pytest.raises(AttributeError, match=r"module 'python_sbom.backend' has no attribute 'build_everything'"):
        backend.build_everything  # ruff: ignore[useless-expression] # the lookup is the test


def test_backend_object_reference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / f"{tmp_path.name}.py").write_text(
        "import types\nimport flit_core.buildapi as flit\n\n"
        "holder = types.SimpleNamespace(api=types.SimpleNamespace(build_wheel=flit.build_wheel))\n",
        encoding="utf-8",
    )
    root = write_project(tmp_path / "project", f"build-backend = '{tmp_path.name}:holder.api'\n", monkeypatch)
    assert validate(root / "dist" / backend.build_wheel(str(root / "dist")), frozenset({"MIT"})) == []


def test_missing_backend_option(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_project(tmp_path / "project", "", monkeypatch)
    with pytest.raises(SbomError, match=r"names no backend to wrap; set build-backend in \[tool.python-sbom\]"):
        backend.build_wheel(str(tmp_path / "dist"))


def test_refuses_to_wrap_itself(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_project(tmp_path / "project", "build-backend = 'python_sbom.backend'\n", monkeypatch)
    with pytest.raises(SbomError, match=r"names python_sbom.backend, which would wrap itself"):
        backend.build_sdist(str(tmp_path / "dist"))


def test_editable_wheel_has_no_sbom(project: Path) -> None:
    # the module-level hook lookup types every optional hook alike, so the name is narrowed here
    name = backend.build_editable(str(project / "dist"))
    assert isinstance(name, str)
    wheel = project / "dist" / name
    assert not [name for name in zipfile.ZipFile(wheel).namelist() if "/sboms/" in name]


@pytest.fixture
def checkout(tmp_path: Path, git: Git, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = write_project(tmp_path / "checkout", "build-backend = 'flit_core.buildapi'\n", monkeypatch)
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "--message", "first")
    return root


def test_sdist_records_clean_revision(checkout: Path, git: Git) -> None:
    with tarfile.open(checkout / "dist" / backend.build_sdist(str(checkout / "dist"))) as archive:
        handle = archive.extractfile("example-1.0/.python-sbom-revision")
        assert handle is not None
        assert handle.read() == f"node: {git('rev-parse', 'HEAD')}\n".encode()


def test_sdist_revision_keeps_the_backend_times(checkout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    sdist = checkout / "dist" / backend.build_sdist(str(checkout / "dist"))
    members = sdist_members(sdist)
    assert members[".python-sbom-revision"].mtime == max(member.mtime for member in members.values())
    # the gzip header's time, bytes 4 to 8, is the one the backend took from SOURCE_DATE_EPOCH
    assert int.from_bytes(sdist.read_bytes()[4:8], "little") == 1700000000


def sdist_members(sdist: Path) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(sdist) as archive:
        return {member.name.split("/", 1)[-1]: member for member in archive.getmembers()}


def test_sdist_of_dirty_checkout_records_no_revision(checkout: Path) -> None:
    (checkout / "LICENSE").write_text("changed\n", encoding="utf-8")
    sdist = checkout / "dist" / backend.build_sdist(str(checkout / "dist"))
    assert ".python-sbom-revision" not in sdist_members(sdist)


def test_sdist_without_top_directory(checkout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def empty_sdist(sdist_directory: str, config_settings: Mapping[str, str] | None = None) -> str:  # ruff: ignore[unused-function-argument] # the hook's signature
        with tarfile.open(Path(sdist_directory) / "example-1.0.tar.gz", "w:gz"):
            pass
        return "example-1.0.tar.gz"

    monkeypatch.setattr(flit_core.buildapi, "build_sdist", empty_sdist)
    with pytest.raises(SbomError, match=r"has no top-level directory to add \.python-sbom-revision to"):
        backend.build_sdist(str(checkout / "dist"))
    assert sorted(path.name for path in (checkout / "dist").iterdir()) == ["example-1.0.tar.gz"]
