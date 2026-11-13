from __future__ import annotations

import gc
import json
import shutil
import tarfile
import tempfile
import time
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import SbomError
from python_sbom._validate._artifact import validate

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import BuildWheel

    from python_sbom._model._types import Document  # simplint: ignore[private-import-path]  # test uses internal model
    from tests.conftest import Git

_SBOM: Final[str] = "example-1.0.dist-info/sboms/example.cdx.json"
# a later hook that changes what the wheel declares and how it is tagged, after the SBOM hook's turn
_RETAG: Final[str] = """\
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class Retag(BuildHookInterface):
    def initialize(self, version, build_data):
        build_data["dependencies"].append("late-dependency>=1")
        build_data["tag"] = "py3-none-manylinux_2_17_x86_64"
"""
# a hook after the SBOM hook that fails the build, before hatchling writes anything
_BREAK: Final[str] = """\
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class Break(BuildHookInterface):
    def initialize(self, version, build_data):
        raise RuntimeError("broken")
"""


def test_wheel_carries_valid_sbom(project: Path, build_wheel: BuildWheel) -> None:
    assert validate(build_wheel(project), frozenset({"MIT"})) == []


@pytest.fixture
def retagged_wheel(project: Path, build_wheel: BuildWheel) -> Path:
    (project / "hatch_build.py").write_text(_RETAG, encoding="utf-8")
    configure(project, "[tool.hatch.build.hooks.custom]\n")
    return build_wheel(project)


def configure(root: Path, tables: str) -> None:
    pyproject = root / "pyproject.toml"
    pyproject.write_text(f"{pyproject.read_text(encoding='utf-8')}{tables}", encoding="utf-8")


def test_sbom_lists_dependencies_a_later_hook_adds(retagged_wheel: Path) -> None:
    assert [component["name"] for component in sbom_of(retagged_wheel)["components"]] == [
        "packaging",
        "late-dependency",
    ]


def sbom_of(wheel: Path, name: str = _SBOM) -> Document:
    return json.loads(zipfile.ZipFile(wheel).read(name))


def test_sbom_names_the_retagged_wheel(retagged_wheel: Path) -> None:
    references = sbom_of(retagged_wheel)["metadata"]["component"]["externalReferences"]
    assert {reference["type"]: reference["url"] for reference in references}["attestation"] == (
        f"https://pypi.org/integrity/Example/1.0/{retagged_wheel.name}/provenance"
    )


def test_later_hook_retags_the_wheel(retagged_wheel: Path) -> None:
    assert retagged_wheel.name == "example-1.0-py3-none-manylinux_2_17_x86_64.whl"


def test_project_table_options(project: Path, build_wheel: BuildWheel) -> None:
    configure(
        project,
        "enable-by-default = true\nrequire-runtime-dependencies = false\n"
        "[tool.python-sbom]\ndefault-branch = 'dev'\nsupplier = { name = 'Example Org' }\n",
    )
    root = sbom_of(build_wheel(project))["metadata"]["component"]
    assert (root.get("supplier"), root["externalReferences"][-1]) == (
        {"name": "Example Org", "url": []},
        {"type": "license", "url": "https://github.com/example/example/blob/dev/LICENSE"},
    )


def test_hook_table_refuses_python_sbom_options(project: Path, build_wheel: BuildWheel) -> None:
    configure(project, "default-branch = 'trunk'\n")
    with pytest.raises(SbomError, match=r"hook's table holds default-branch; move python-sbom's options"):
        build_wheel(project)


def test_reproducible_build_uses_hatchling_time(project: Path, build_wheel: BuildWheel) -> None:
    assert sbom_of(build_wheel(project))["metadata"]["timestamp"] == "2020-02-02T00:00:00+00:00"


def test_non_reproducible_build_uses_current_time(project: Path, build_wheel: BuildWheel) -> None:
    (project / "pyproject.toml").write_text(
        (project / "pyproject.toml")
        .read_text(encoding="utf-8")
        .replace("[tool.hatch.build.targets.wheel]\n", "[tool.hatch.build.targets.wheel]\nreproducible = false\n"),
        encoding="utf-8",
    )
    before = time.time()
    timestamp = sbom_of(build_wheel(project))["metadata"]["timestamp"]
    assert timestamp >= time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(before)))


def test_source_date_epoch_wins(project: Path, build_wheel: BuildWheel, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert sbom_of(build_wheel(project))["metadata"]["timestamp"] == "2023-11-14T22:13:20+00:00"


def test_editable_wheel_has_no_sbom(project: Path, build_wheel: BuildWheel) -> None:
    # a .pth editable, which needs no editables package
    pyproject = project / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            "[tool.hatch.build.targets.wheel]\n", "[tool.hatch.build.targets.wheel]\ndev-mode-dirs = ['src']\n"
        ),
        encoding="utf-8",
    )
    names = zipfile.ZipFile(build_wheel(project, version="editable")).namelist()
    assert not [name for name in names if "/sboms/" in name]


def test_sdist_has_no_sbom(project: Path, build_wheel: BuildWheel) -> None:
    configure(project, "[tool.hatch.build.targets.sdist.hooks.python-sbom]\n")
    sdist = build_wheel(project, version="standard", target="sdist")
    assert sdist.name.endswith(".tar.gz")
    assert "sboms" not in sdist.read_bytes().decode("latin-1")


def test_content_provider_option(project: Path, build_wheel: BuildWheel, tmp_path: Path) -> None:
    (project / f"{tmp_path.name}.py").write_text(
        "from python_sbom import ContentProvider, Contributions\n\n\n"
        "class Content(ContentProvider):\n"
        "    def contributions(self, context):\n"
        "        return Contributions("
        " root_properties=[{'name': 'extra:by', 'value': 'hook'}])\n",
        encoding="utf-8",
    )
    configure(project, f"[tool.python-sbom]\ncontent-provider = '{tmp_path.name}:Content'\n")
    document = sbom_of(build_wheel(project))
    assert {"name": "extra:by", "value": "hook"} in document["metadata"]["component"]["properties"]
    assert document["metadata"]["tools"]["components"][0]["name"] == f"{tmp_path.name}.py"


def test_seeder_bundles_described(seeder: Path, build_wheel: BuildWheel) -> None:
    (pip,) = sbom_of(build_wheel(seeder), "seeder-1.0.dist-info/sboms/seeder.cdx.json")["components"]
    assert pip.get("properties", [])[:3] == [
        {"name": "seeder:bundled-wheel", "value": "seeder/embed/pip-1.0-py3-none-any.whl"},
        {"name": "seeder:seeded-for-python", "value": "3.14"},
        {"name": "seeder:seeded-for-python", "value": "3.15"},
    ]


def test_seeder_hook_script_is_a_tool(seeder: Path, build_wheel: BuildWheel) -> None:
    document = sbom_of(build_wheel(seeder), "seeder-1.0.dist-info/sboms/seeder.cdx.json")
    assert document["metadata"]["tools"]["components"][0]["name"] == "hatch_build.py"


def test_seeder_supplier(seeder: Path, build_wheel: BuildWheel) -> None:
    document = sbom_of(build_wheel(seeder), "seeder-1.0.dist-info/sboms/seeder.cdx.json")
    assert document["metadata"].get("supplier") == {"name": "Example Org", "url": ["https://example.org"]}


def test_seeder_bundled_wheel_supplier(seeder: Path, build_wheel: BuildWheel) -> None:
    document = sbom_of(build_wheel(seeder), "seeder-1.0.dist-info/sboms/seeder.cdx.json")
    assert document["components"][0].get("supplier") == {"name": "Example Org", "url": ["https://example.org"]}


@pytest.fixture
def checkout(project: Path, tmp_path: Path, git: Git) -> Path:
    shutil.copytree(project, target := tmp_path / "checkout", dirs_exist_ok=True)
    git("add", ".")
    git("commit", "--quiet", "--message", "first")
    return target


def test_sdist_records_clean_revision(checkout: Path, git: Git, build_wheel: BuildWheel) -> None:
    files = sdist_files(build_wheel(checkout, target="sdist"))
    assert files.get(".python-sbom-revision") == f"node: {git('rev-parse', 'HEAD')}\n".encode()


def sdist_files(sdist: Path) -> dict[str, bytes]:
    with tarfile.open(sdist) as archive:
        return {
            member.name.split("/", 1)[1]: handle.read()
            for member in archive.getmembers()
            if (handle := archive.extractfile(member)) is not None
        }


def test_sdist_of_dirty_checkout_records_no_revision(checkout: Path, build_wheel: BuildWheel) -> None:
    (checkout / "LICENSE").write_text("changed\n", encoding="utf-8")
    assert ".python-sbom-revision" not in sdist_files(build_wheel(checkout, target="sdist"))


def test_each_build_reads_the_revision(checkout: Path, git: Git, build_wheel: BuildWheel) -> None:
    build_wheel(checkout, target="sdist")
    (checkout / "LICENSE").write_text("changed\n", encoding="utf-8")
    git("commit", "--quiet", "--all", "--message", "second")
    files = sdist_files(build_wheel(checkout, target="sdist"))
    assert files.get(".python-sbom-revision") == f"node: {git('rev-parse', 'HEAD')}\n".encode()


@pytest.fixture
def temp_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (directory := tmp_path / "temp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(directory))
    monkeypatch.setenv("TMPDIR", str(directory))
    return directory


@pytest.mark.parametrize("target", [pytest.param("sdist", id="sdist"), pytest.param("wheel", id="wheel")])
def test_build_leaves_no_temporary_files(checkout: Path, temp_dir: Path, build_wheel: BuildWheel, target: str) -> None:
    build_wheel(checkout, target=target)
    assert list(temp_dir.iterdir()) == []


def test_failed_build_leaves_no_temporary_files(
    checkout: Path, temp_dir: Path, git: Git, build_wheel: BuildWheel
) -> None:
    (checkout / "hatch_build.py").write_text(_BREAK, encoding="utf-8")
    # hatchling compiles the hook script, which must not make the checkout dirty, so the sdist records the revision
    (checkout / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    configure(checkout, "[tool.hatch.build.hooks.custom]\n")
    git("add", ".")
    git("commit", "--quiet", "--message", "break the build")
    with pytest.raises(RuntimeError, match="broken"):
        build_wheel(checkout, target="sdist")
    # the failed build's frames hold the hook in a reference cycle
    gc.collect()
    assert list(temp_dir.iterdir()) == []
