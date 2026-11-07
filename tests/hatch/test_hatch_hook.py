from __future__ import annotations

import json
import time
import zipfile
from typing import TYPE_CHECKING, Final

from python_sbom import validate_wheel

if TYPE_CHECKING:
    from pathlib import Path

    import pytest
    from conftest import BuildWheel

    from python_sbom import Document

_SBOM: Final[str] = "example-1.0.dist-info/sboms/example.cdx.json"
# a later hook that changes what the wheel declares and how it is tagged, after the SBOM hook's turn
_RETAG: Final[str] = """\
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class Retag(BuildHookInterface):
    def initialize(self, version, build_data):
        build_data["dependencies"].append("late-dependency>=1")
        build_data["tag"] = "py3-none-manylinux_2_17_x86_64"
"""


def sbom_of(wheel: Path, name: str = _SBOM) -> Document:
    return json.loads(zipfile.ZipFile(wheel).read(name))


def test_wheel_carries_valid_sbom(project: Path, build_wheel: BuildWheel) -> None:
    assert validate_wheel(build_wheel(project), frozenset({"MIT"})) == []


def test_sbom_describes_the_built_wheel(project: Path, build_wheel: BuildWheel) -> None:
    (project / "hatch_build.py").write_text(_RETAG, encoding="utf-8")
    configure(project, "[tool.hatch.build.hooks.custom]\n")
    document = sbom_of(wheel := build_wheel(project))
    references = {
        reference["type"]: reference["url"] for reference in document["metadata"]["component"]["externalReferences"]
    }
    assert [component["name"] for component in document["components"]] == ["packaging", "late-dependency"]
    assert references["attestation"] == f"https://pypi.org/integrity/Example/1.0/{wheel.name}/provenance"
    assert wheel.name == "example-1.0-py3-none-manylinux_2_17_x86_64.whl"


def configure(root: Path, tables: str) -> None:
    pyproject = root / "pyproject.toml"
    pyproject.write_text(f"{pyproject.read_text(encoding='utf-8')}{tables}", encoding="utf-8")


def test_hook_table_overrides_project_table(project: Path, build_wheel: BuildWheel) -> None:
    configure(
        project,
        "enable-by-default = true\nrequire-runtime-dependencies = false\ndefault-branch = 'trunk'\n"
        "[tool.python-sbom]\ndefault-branch = 'dev'\nsupplier = { name = 'Example Org' }\n",
    )
    root = sbom_of(build_wheel(project))["metadata"]["component"]
    assert {"type": "license", "url": "https://github.com/example/example/blob/trunk/LICENSE"} in root[
        "externalReferences"
    ]
    assert root.get("supplier") == {"name": "Example Org", "url": []}


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
        "    def contributions(self, request):\n"
        "        return Contributions(components=[], dependencies=[], tools=[],"
        " root_properties=[{'name': 'example:by', 'value': 'hook'}])\n",
        encoding="utf-8",
    )
    configure(project, f"content-provider = '{tmp_path.name}:Content'\n")
    document = sbom_of(build_wheel(project))
    assert {"name": "example:by", "value": "hook"} in document["metadata"]["component"]["properties"]
    assert document["metadata"]["tools"]["components"][0]["name"] == f"{tmp_path.name}.py"


def test_seeder_bundles_described(seeder: Path, build_wheel: BuildWheel) -> None:
    (pip,) = sbom_of(build_wheel(seeder), "seeder-1.0.dist-info/sboms/seeder.cdx.json")["components"]
    assert pip.get("properties", [])[:3] == [
        {"name": "seeder:bundled-wheel", "value": "src/seeder/embed/pip-1.0-py3-none-any.whl"},
        {"name": "seeder:seeded-for-python", "value": "3.14"},
        {"name": "seeder:seeded-for-python", "value": "3.15"},
    ]


def test_seeder_hook_script_is_a_tool(seeder: Path, build_wheel: BuildWheel) -> None:
    document = sbom_of(build_wheel(seeder), "seeder-1.0.dist-info/sboms/seeder.cdx.json")
    assert document["metadata"]["tools"]["components"][0]["name"] == "hatch_build.py"


def test_seeder_supplier(seeder: Path, build_wheel: BuildWheel) -> None:
    document = sbom_of(build_wheel(seeder), "seeder-1.0.dist-info/sboms/seeder.cdx.json")
    assert document["metadata"].get("supplier") == {"name": "Example Org", "url": ["https://example.org"]}
