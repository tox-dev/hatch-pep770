from __future__ import annotations

import json
import runpy
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._cli._main import main
from python_sbom._formats._json import dumps
from python_sbom.version import __version__

if TYPE_CHECKING:
    from conftest import Describe, Install, WriteWheel

    from python_sbom._model._types import Document

_SBOM: Final[str] = "native-1.0.dist-info/sboms/native.cdx.json"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (root := tmp_path / "project").mkdir()
    (root / "pyproject.toml").write_text("[tool.python-sbom]\ndefault-branch = 'trunk'\n", encoding="utf-8")
    return root


@pytest.fixture
def wheel(tmp_path: Path, write_wheel: WriteWheel) -> Path:
    return write_wheel(
        tmp_path / "dist" / "native-1.0-py3-none-any.whl",
        {"native/__init__.py": b"", "native-1.0.dist-info/METADATA": b"Name: native\nVersion: 1.0\n"},
    )


def test_embed(
    project: Path, wheel: Path, tmp_path: Path, install: Install, capsys: pytest.CaptureFixture[str]
) -> None:
    commit = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"
    install(site := tmp_path / "site", "Name: meson-python\nVersion: 0.18\n", {})
    main(["embed", str(wheel), "--root", str(project), "--commit", commit, "--build-env", str(site)])
    document = embedded(wheel)
    assert capsys.readouterr().out == f"wrote {_SBOM} into {wheel.name}\n"
    assert {"name": "native:vcs-commit", "value": commit} in document["metadata"]["component"]["properties"]
    assert [tool["name"] for tool in document["metadata"]["tools"]["components"][1:]] == ["meson-python"]


def embedded(wheel: Path) -> Document:
    return json.loads(zipfile.ZipFile(wheel).read(_SBOM))


def test_embed_defaults_to_current_directory(project: Path, wheel: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(project)
    monkeypatch.setenv("PYTHON_SBOM_COMMIT", "cafecafecafecafecafecafecafecafecafecafe")
    main(["embed", str(wheel), "--build-env", str(project)])
    assert {"name": "native:vcs-commit", "value": "cafecafecafecafecafecafecafecafecafecafe"} in embedded(wheel)[
        "metadata"
    ]["component"]["properties"]


@pytest.mark.parametrize(
    ("option", "table"),
    [
        pytest.param(["--content-provider", "MODULE:Native"], "", id="option"),
        pytest.param([], "content-provider = 'MODULE:Native'\n", id="setting"),
    ],
)
def test_embed_with_content_provider(tmp_path: Path, project: Path, wheel: Path, option: list[str], table: str) -> None:
    # a module name unique to the test, so the import cache never hands over another test's module
    provider = """\
from python_sbom import ContentProvider, Contributions


class Native(ContentProvider):
    def contributions(self, context):
        return Contributions(
            root_properties=[{"name": "extra:by", "value": "cli"}]
        )
"""
    (project / f"{tmp_path.name}.py").write_text(provider, encoding="utf-8")
    (project / "pyproject.toml").write_text(f"[tool.python-sbom]\n{table.replace('MODULE', tmp_path.name)}")
    main([
        "embed",
        str(wheel),
        "--root",
        str(project),
        "--build-env",
        str(project),
        *(argument.replace("MODULE", tmp_path.name) for argument in option),
    ])
    document = embedded(wheel)
    assert {"name": "extra:by", "value": "cli"} in document["metadata"]["component"]["properties"]
    assert document["metadata"]["tools"]["components"][0]["name"] == f"{tmp_path.name}.py"


def test_error_without_traceback(tmp_path: Path, wheel: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["embed", str(wheel), "--root", str(tmp_path)])
    assert exit_info.value.code == 1
    assert capsys.readouterr().err == f"python-sbom: {tmp_path} has no pyproject.toml to read [tool.python-sbom] from\n"


def test_spdx(tmp_path: Path, describe: Describe) -> None:
    (source := tmp_path / "example.cdx.json").write_bytes(dumps(describe()))
    main(["spdx", str(source), str(target := tmp_path / "example.spdx.json")])
    assert json.loads(target.read_text(encoding="utf-8"))["spdxVersion"] == "SPDX-2.3"


def test_validate_directory(project: Path, wheel: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["embed", str(wheel), "--root", str(project), "--build-env", str(project)])
    capsys.readouterr()
    main(["validate", str(wheel.parent), "--allow-license", "MIT"])
    assert capsys.readouterr().out == f"SBOM in {wheel.name} is valid\n"


def test_validate_reports_problems(wheel: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["validate", str(wheel)])
    assert capsys.readouterr().err == f"SBOM invalid: {wheel.name}: no SBOM found in {wheel.name}\n"


@pytest.fixture
def crowded_wheel(tmp_path: Path, write_wheel: WriteWheel) -> Path:
    # 100 groups of 50 parts, 5,100 components in all, yet no array long enough to slow the schema check
    groups = [
        {
            "type": "library",
            "name": f"g{group}",
            "components": [{"type": "library", "name": f"p{part}"} for part in range(50)],
        }
        for group in range(100)
    ]
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": groups}).encode()
    return write_wheel(tmp_path / "native-1.0-py3-none-any.whl", {"native-1.0.dist-info/METADATA": b"", _SBOM: sbom})


def test_validate_max_components_sets_the_cap(crowded_wheel: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["validate", str(crowded_wheel), "--max-components", "5000"])
    assert capsys.readouterr().err == (
        f"SBOM invalid: {crowded_wheel.name}: {_SBOM}: lists more than 5000 components, nested ones included;"
        " pass a higher --max-components to check it\n"
    )


def test_validate_default_cap_admits_thousands(crowded_wheel: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["validate", str(crowded_wheel)])
    assert capsys.readouterr().out == f"SBOM in {crowded_wheel.name} is valid\n"


def test_validate_without_wheels(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["validate", str(tmp_path)])
    assert capsys.readouterr().err == f"no wheel found in {tmp_path}\n"


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["python-sbom", "--help"])
    with pytest.raises(SystemExit):
        runpy.run_module("python_sbom", run_name="__main__")
    assert capsys.readouterr().out.startswith("usage: python-sbom ")


def test_console_script() -> None:
    script = Path(sys.executable).parent / "python-sbom"
    assert subprocess.check_output([script, "--help"], text=True).startswith("usage: python-sbom ")


@pytest.fixture
def zipapp(tmp_path: Path) -> Path:
    with zipfile.ZipFile(target := tmp_path / "app.pyz", "w") as handle:
        handle.writestr("__main__.py", "import app\n")
        handle.writestr("app-1.0.dist-info/METADATA", "Name: app\nVersion: 1.0\nLicense-Expression: MIT\n")
        handle.writestr("app/__init__.py", "")
    return target


def test_archive_writes_sbom_next_to_archive(project: Path, zipapp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["archive", str(zipapp), "--root", str(project), "--build-env", str(project)])
    assert (
        capsys.readouterr().out,
        json.loads(zipapp.with_name("app.pyz.cdx.json").read_text())["metadata"]["component"]["name"],
    ) == (
        f"wrote {zipapp.with_name('app.pyz.cdx.json')}\n",
        "app.pyz",
    )


def test_archive_embeds_sbom(project: Path, zipapp: Path, tmp_path: Path) -> None:
    (project / "build_app.py").write_text("", encoding="utf-8")
    main([
        "archive",
        str(zipapp),
        "--root",
        str(project),
        "--build-env",
        str(project),
        "--build-script",
        "build_app.py",
        "--output",
        str(tmp_path / "out.json"),
        "--embed",
    ])
    entry = zipfile.ZipFile(zipapp).getinfo("app.pyz.cdx.json")
    assert (entry.create_system, entry.external_attr, zipfile.ZipFile(zipapp).read(entry)) == (
        3,
        0o644 << 16,
        (tmp_path / "out.json").read_bytes(),
    )


def test_archive_refuses_second_embed(project: Path, zipapp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    arguments = ["archive", str(zipapp), "--root", str(project), "--build-env", str(project), "--embed"]
    main(arguments)
    capsys.readouterr()
    with pytest.raises(SystemExit):
        main(arguments)
    assert capsys.readouterr().err == "python-sbom: app.pyz already holds app.pyz.cdx.json\n"


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out == f"python-sbom {__version__}\n"


def test_spdx_refuses_non_document(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source := tmp_path / "other.json").write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["spdx", str(source), str(tmp_path / "out.json")])
    assert capsys.readouterr().err == f"python-sbom: {source} is not a CycloneDX document python-sbom can render\n"


def test_spdx_refuses_malformed_document(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    document = {"metadata": {"component": {"bom-ref": "app", "name": "app"}}, "components": [{"name": "x"}]}
    (source := tmp_path / "broken.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["spdx", str(source), str(tmp_path / "out.json")])
    assert capsys.readouterr().err.startswith(
        f"python-sbom: {source} is not a CycloneDX document python-sbom can render: "
    )
