from __future__ import annotations

import json
import runpy
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import dumps, main

if TYPE_CHECKING:
    from conftest import Describe, Install, WriteWheel

    from python_sbom import Document

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
    install(site := tmp_path / "site", "Name: meson-python\nVersion: 0.18\n", {})
    main(["embed", str(wheel), "--root", str(project), "--commit", "c0ffee", "--build-env", str(site)])
    document = embedded(wheel)
    assert capsys.readouterr().out == f"wrote {_SBOM} into {wheel.name}\n"
    assert {"name": "native:vcs-commit", "value": "c0ffee"} in document["metadata"]["component"]["properties"]
    assert [tool["name"] for tool in document["metadata"]["tools"]["components"][1:]] == ["meson-python"]


def embedded(wheel: Path) -> Document:
    return json.loads(zipfile.ZipFile(wheel).read(_SBOM))


def test_embed_defaults_to_current_directory(project: Path, wheel: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(project)
    monkeypatch.setenv("PYTHON_SBOM_COMMIT", "cafe")
    main(["embed", str(wheel), "--build-env", str(project)])
    assert {"name": "native:vcs-commit", "value": "cafe"} in embedded(wheel)["metadata"]["component"]["properties"]


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
    def contributions(self, request):
        return Contributions(
            components=[], dependencies=[], root_properties=[{"name": "native:by", "value": "cli"}], tools=[]
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
    assert {"name": "native:by", "value": "cli"} in document["metadata"]["component"]["properties"]
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
    assert capsys.readouterr().err == f"SBOM invalid: {wheel.name}: no .dist-info/sboms/*.cdx.json found in the wheel\n"


def test_validate_without_wheels(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["validate", str(tmp_path)])
    assert capsys.readouterr().err == f"no wheel found in {tmp_path}\n"


def test_validate_without_extra(
    wheel: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "cyclonedx.schema", None)
    monkeypatch.delitem(sys.modules, "python_sbom._validate._schemas", raising=False)
    zipfile.ZipFile(wheel, "a").writestr(_SBOM, b"{}")
    with pytest.raises(SystemExit):
        main(["validate", str(wheel)])
    assert capsys.readouterr().err == (
        "python-sbom: validation needs the validate extra: pip install 'python-sbom[validate]'\n"
    )


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["python-sbom", "--help"])
    with pytest.raises(SystemExit):
        runpy.run_module("python_sbom", run_name="__main__")
    assert capsys.readouterr().out.startswith("usage: python-sbom ")


def test_console_script() -> None:
    script = Path(sys.executable).parent / "python-sbom"
    assert subprocess.check_output([script, "--help"], text=True).startswith("usage: python-sbom ")
