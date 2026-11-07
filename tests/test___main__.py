from __future__ import annotations

import json
import sys
import zipfile
from typing import TYPE_CHECKING

import pytest

from hatch_pep770.__main__ import main
from hatch_pep770.spdx import to_spdx

if TYPE_CHECKING:
    from pathlib import Path

    from hatch_pep770.cyclonedx import Document


@pytest.fixture
def wheel(sbom_document: Document, tmp_path: Path) -> Path:
    (dist := tmp_path / "dist").mkdir()
    with zipfile.ZipFile(path := dist / "example-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("example-1.0.dist-info/sboms/example.cdx.json", json.dumps(sbom_document))
    return path


def test_main_spdx(sbom_document: Document, tmp_path: Path) -> None:
    (source := tmp_path / "example.cdx.json").write_text(json.dumps(sbom_document), encoding="utf-8")
    assert (main(["spdx", str(source), str(target := tmp_path / "example.spdx.json")]), target.read_bytes()) == (
        0,
        f"{json.dumps(to_spdx(sbom_document), indent=2)}\n".encode(),
    )


@pytest.mark.parametrize(
    "target", [pytest.param("example-1.0-py3-none-any.whl", id="wheel"), pytest.param(".", id="directory")]
)
def test_main_validate(wheel: Path, capsys: pytest.CaptureFixture[str], target: str) -> None:
    assert (main(["validate", str(wheel.parent / target), "--allow-license", "MIT"]), capsys.readouterr().out) == (
        0,
        "SBOM in example-1.0-py3-none-any.whl is valid\n",
    )


def test_main_validate_problems(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with zipfile.ZipFile(wheel := tmp_path / "example-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("example-1.0.dist-info/METADATA", "Name: example\n")
    assert (main(["validate", str(wheel)]), capsys.readouterr().err) == (
        1,
        "SBOM invalid: example-1.0-py3-none-any.whl: no .dist-info/sboms/*.cdx.json found in the wheel\n",
    )


def test_main_validate_no_wheel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (main(["validate", str(tmp_path)]), capsys.readouterr().err) == (1, f"no wheel found in {tmp_path}\n")


def test_main_module(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["hatch-pep770", "--help"])
    with pytest.raises(SystemExit):
        main()
    assert "usage: hatch-pep770" in capsys.readouterr().out
