from __future__ import annotations

import json
import tarfile
import zipfile
from typing import TYPE_CHECKING, Final

import pytest
from setuptools import build_meta
from setuptools.dist import Distribution

from python_sbom._errors import SbomError
from python_sbom._validate._artifact import validate
from python_sbom.setuptools import finalize_distribution_options

if TYPE_CHECKING:
    from pathlib import Path

    from tests.conftest import Git

# setuptools-scm, which the dev environment installs through hatch-vcs, warns about its file finder in every setuptools
# build
pytestmark: Final[pytest.MarkDecorator] = pytest.mark.filterwarnings(
    "ignore:The setuptools.file_finders entry point is deprecated:DeprecationWarning"
)

# the project's own wheel command, which the plugin must keep
_SETUP: Final[str] = """\
from pathlib import Path

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel


class Wheel(bdist_wheel):
    def run(self):
        Path("custom-ran").write_text("yes")
        super().run()


setup(cmdclass={"bdist_wheel": Wheel})
"""


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return write_project(tmp_path / "project", "\n[tool.python-sbom]\n", monkeypatch)


def write_project(root: Path, tables: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    (root / "example").mkdir(parents=True, exist_ok=True)
    (root / "example" / "__init__.py").write_text("", encoding="utf-8")
    (root / "LICENSE").write_text("Copyright (c) 2026 Example\n\nMIT terms\n", encoding="utf-8")
    project = """\
[build-system]
build-backend = "setuptools.build_meta"
requires = ["setuptools>=77", "python-sbom"]

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
    assert validate(project / "dist" / build_meta.build_wheel(str(project / "dist")), frozenset({"MIT"})) == []


def test_project_wheel_command_is_kept(project: Path) -> None:
    (project / "setup.py").write_text(_SETUP, encoding="utf-8")
    wheel = project / "dist" / build_meta.build_wheel(str(project / "dist"))
    assert ((project / "custom-ran").read_text(encoding="utf-8"), sboms(wheel)) == (
        "yes",
        ["example-1.0.dist-info/sboms/example.cdx.json"],
    )


def sboms(wheel: Path) -> list[str]:
    return [name for name in zipfile.ZipFile(wheel).namelist() if "/sboms/" in name]


def test_wheel_command_that_writes_no_wheel(project: Path) -> None:
    (project / "setup.py").write_text(
        "from setuptools import setup\nfrom setuptools.command.bdist_wheel import bdist_wheel\n\n\n"
        "class Wheel(bdist_wheel):\n    def run(self):\n        pass\n\n\nsetup(cmdclass={'bdist_wheel': Wheel})\n",
        encoding="utf-8",
    )
    with pytest.raises(SbomError, match=r"Wheel wrote no wheel to describe"):
        build_meta.build_wheel(str(project / "dist"))


@pytest.mark.parametrize(
    ("commands", "named"),
    [
        pytest.param('bdist_wheel = "custom:Wheel"', "bdist_wheel", id="wheel"),
        pytest.param('sdist = "custom:Sdist"\nbdist_wheel = "custom:Wheel"', "bdist_wheel, sdist", id="both"),
    ],
)
def test_pyproject_replacing_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, commands: str, named: str
) -> None:
    write_project(
        tmp_path / "project", f"\n[tool.python-sbom]\n\n[tool.setuptools.cmdclass]\n{commands}\n", monkeypatch
    )
    with pytest.raises(SbomError, match=rf"^\[tool.setuptools.cmdclass\] replaces {named} after python-sbom wraps it"):
        finalize_distribution_options(Distribution())


def test_project_without_table_has_no_sbom(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = write_project(tmp_path / "project", "", monkeypatch)
    assert sboms(root / "dist" / build_meta.build_wheel(str(root / "dist"))) == []


# setuptools tells about every editable build with a warning, which the suite turns into an error
@pytest.mark.filterwarnings("ignore::setuptools.warnings.InformationOnly")
def test_editable_wheel_has_no_sbom(project: Path) -> None:
    assert sboms(project / "dist" / build_meta.build_editable(str(project / "dist"))) == []


def test_project_without_pyproject_is_left_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    distribution = Distribution()
    commands = dict(distribution.cmdclass)
    finalize_distribution_options(distribution)
    assert distribution.cmdclass == commands


def test_invalid_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.python-sbom\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SbomError, match=r"pyproject.toml is not valid TOML"):
        finalize_distribution_options(Distribution())


@pytest.fixture
def checkout(tmp_path: Path, git: Git, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = write_project(tmp_path / "checkout", "\n[tool.python-sbom]\n", monkeypatch)
    (root / ".gitignore").write_text("dist/\nbuild/\n*.egg-info/\n", encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "--message", "first")
    return root


def test_sdist_records_clean_revision(checkout: Path, git: Git) -> None:
    sdist = checkout / "dist" / build_meta.build_sdist(str(checkout / "dist"))
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
    assert revision_of(checkout / "dist" / build_meta.build_sdist(str(checkout / "dist"))) is None


def test_wheel_from_sdist_names_its_commit(checkout: Path, git: Git, tmp_path: Path) -> None:
    with tarfile.open(checkout / "dist" / build_meta.build_sdist(str(checkout / "dist"))) as archive:
        archive.extractall(tmp_path / "unpacked", filter="data")
    unpacked = tmp_path / "unpacked" / "example-1.0"
    with pytest.MonkeyPatch.context() as patch:
        patch.chdir(unpacked)
        (unpacked / "dist").mkdir()
        wheel = unpacked / "dist" / build_meta.build_wheel(str(unpacked / "dist"))
    sbom = zipfile.ZipFile(wheel).read("example-1.0.dist-info/sboms/example.cdx.json")
    component = json.loads(sbom)["metadata"]["component"]
    assert git("rev-parse", "HEAD") in json.dumps(component)
