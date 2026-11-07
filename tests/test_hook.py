from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from conftest import BUNDLED, HOOK, build_hook_sbom
from hatchling.builders.sdist import SdistBuilder
from hatchling.builders.wheel import WheelBuilder

from python_sbom import validate_wheel

if TYPE_CHECKING:
    from conftest import BundleWheel, WriteProject

    from python_sbom import Document


def test_wheel_embeds_sbom(write_project: WriteProject, tmp_path: Path) -> None:
    with zipfile.ZipFile(_build_wheel(write_project(), tmp_path / "dist")) as archive:
        sbom: Final[bytes] = archive.read("example-1.0.dist-info/sboms/example.cdx.json")
        record: Final[str] = archive.read("example-1.0.dist-info/RECORD").decode("utf-8")
    assert ("example-1.0.dist-info/sboms/example.cdx.json,sha256=" in record, json.loads(sbom)["bomFormat"]) == (
        True,
        "CycloneDX",
    )


def _build_wheel(root: Path, out: Path) -> Path:
    (artifact,) = WheelBuilder(str(root)).build(directory=str(out), versions=["standard"])
    return Path(artifact)


def test_wheel_sbom_valid(write_project: WriteProject, bundle_wheel: BundleWheel, tmp_path: Path) -> None:
    bundle_wheel({"pip/_vendor/vendor.txt": "urllib3==1.26.4\n"}, "License-Expression: MIT\n")
    wheel: Final[Path] = _build_wheel(write_project(hook=f"{HOOK}{BUNDLED}"), tmp_path / "dist")
    assert validate_wheel(wheel, frozenset({"MIT"})) == []


def test_wheel_reproducible(write_project: WriteProject, tmp_path: Path) -> None:
    root: Final[Path] = write_project()
    assert _build_wheel(root, tmp_path / "first").read_bytes() == _build_wheel(root, tmp_path / "second").read_bytes()


def test_wheel_sbom_directory_removed(write_project: WriteProject) -> None:
    builder: Final[WheelBuilder] = WheelBuilder(str(write_project()))
    build_data = builder.get_default_build_data()
    (hook,) = builder.get_build_hooks(str(builder.root)).values()
    hook.initialize("standard", build_data)
    hook.finalize("standard", build_data, "")
    assert Path(build_data["sbom_files"][0]).parent.exists() is False


def test_sdist_skipped(write_project: WriteProject, tmp_path: Path) -> None:
    # the hook runs for every target, and only a wheel build has somewhere to put an SBOM
    (artifact,) = SdistBuilder(str(write_project())).build(directory=str(tmp_path / "dist"))
    assert Path(artifact).name == "example-1.0.tar.gz"


def test_attestation_tag_from_another_hook(write_project: WriteProject) -> None:
    builder: Final[WheelBuilder] = WheelBuilder(str(write_project()))
    assert _attestations(builder, "tag", "py3-none-linux_x86_64") == [
        "https://pypi.org/integrity/Example/1.0/example-1.0-py3-none-linux_x86_64.whl/provenance"
    ]


def _attestations(builder: WheelBuilder, key: str, value: str | bool) -> list[str]:
    build_data = builder.get_default_build_data()
    build_data[key] = value
    (hook,) = builder.get_build_hooks(str(builder.root)).values()
    hook.initialize("standard", build_data)
    document: Final[Document] = json.loads(Path(build_data["sbom_files"][0]).read_text(encoding="utf-8"))
    references = document["metadata"]["component"].get("externalReferences", [])
    return [reference["url"] for reference in references if reference["type"] == "attestation"]


def test_attestation_tag_inferred(write_project: WriteProject) -> None:
    builder: Final[WheelBuilder] = WheelBuilder(str(write_project()))
    assert _attestations(builder, "infer_tag", True) == [
        f"https://pypi.org/integrity/Example/1.0/example-1.0-{builder.get_best_matching_tag()}.whl/provenance"
    ]


@pytest.mark.parametrize(
    ("urls", "references"),
    [
        pytest.param(
            'urls.Source = "https://github.com/example/example"',
            {"externalReferences": [{"type": "vcs", "url": "https://github.com/example/example/blob/main/build.py"}]},
            id="repository",
        ),
        pytest.param("", {}, id="no-repository"),
    ],
)
def test_custom_build_script_recorded(
    root: Path, write_project: WriteProject, urls: str, references: dict[str, list[dict[str, str]]]
) -> None:
    (script := root / "build.py").write_text(
        "from __future__ import annotations\n\nfrom python_sbom.hatch import SbomBuildHook\n\n\n"
        "def get_build_hook() -> type[SbomBuildHook]:\n    return SbomBuildHook\n",
        encoding="utf-8",
    )
    project = f'[project]\nname = "example"\nversion = "1.0"\n{urls}\n'
    document = build_hook_sbom(
        write_project(hook='[tool.hatch.build.hooks.custom]\npath = "build.py"\n', project=project)
    )
    assert document["metadata"]["tools"]["components"][0] == {
        "type": "application",
        "bom-ref": "tool:build.py",
        "name": "build.py",
        "version": "1.0",
        "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(script.read_bytes()).hexdigest()}],
        **references,
    }


def test_seeder_subclass_adds_properties(seeder: Path, tmp_path: Path) -> None:
    with zipfile.ZipFile(_build_wheel(seeder, tmp_path / "dist")) as archive:
        document: Final[Document] = json.loads(archive.read("seeder-1.0.dist-info/sboms/seeder.cdx.json"))
    assert document["components"][0].get("properties", [])[:3] == [
        {"name": "seeder:bundled-wheel", "value": "src/seeder/embed/pip-1.0-py3-none-any.whl"},
        {"name": "seeder:seeded-for-python", "value": "3.14"},
        {"name": "seeder:seeded-for-python", "value": "3.15"},
    ]


def test_seeder_supplier_and_vendored(seeder: Path, tmp_path: Path) -> None:
    with zipfile.ZipFile(_build_wheel(seeder, tmp_path / "dist")) as archive:
        document: Final[Document] = json.loads(archive.read("seeder-1.0.dist-info/sboms/seeder.cdx.json"))
    pip = document["components"][0]
    assert (
        pip.get("supplier"),
        [child["name"] for child in pip.get("components", []) if child["type"] == "library"],
    ) == (
        {"name": "Example Org", "url": ["https://example.org"]},
        ["urllib3"],
    )


def test_seeder_wheel_valid(seeder: Path, tmp_path: Path) -> None:
    assert validate_wheel(_build_wheel(seeder, tmp_path / "dist"), frozenset({"MIT"})) == []
