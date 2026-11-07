from __future__ import annotations

import json
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import main, to_spdx

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import BuildSbom, MakeWheel

    from python_sbom import Document


def test_cli_embed(make_wheel: MakeWheel, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    wheel: Final[Path] = make_wheel("")
    (tmp_path / "pyproject.toml").write_text('[tool.python-sbom]\nsupplier = { name = "Org" }\n', encoding="utf-8")
    main(["embed", str(wheel), "--root", str(tmp_path)])
    with zipfile.ZipFile(wheel) as archive:
        document: Final[Document] = json.loads(archive.read("native-1.0.dist-info/sboms/native.cdx.json"))
    assert (document["metadata"].get("supplier"), capsys.readouterr().out) == (
        {"name": "Org", "url": []},
        f"wrote native-1.0.dist-info/sboms/native.cdx.json into {wheel.name}\n",
    )


def test_cli_embed_without_settings(make_wheel: MakeWheel, tmp_path: Path) -> None:
    wheel: Final[Path] = make_wheel("")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'native'\n", encoding="utf-8")
    main(["embed", str(wheel), "--root", str(tmp_path)])
    with zipfile.ZipFile(wheel) as archive:
        document: Final[Document] = json.loads(archive.read("native-1.0.dist-info/sboms/native.cdx.json"))
    assert "supplier" not in document["metadata"]


def test_cli_spdx(build_sbom: BuildSbom, tmp_path: Path) -> None:
    document: Final[Document] = build_sbom()
    (source := tmp_path / "example.cdx.json").write_text(json.dumps(document), encoding="utf-8")
    main(["spdx", str(source), str(target := tmp_path / "example.spdx.json")])
    assert target.read_bytes() == f"{json.dumps(to_spdx(document), indent=2)}\n".encode()


@pytest.mark.parametrize(
    "target", [pytest.param("native-1.0-py3-none-any.whl", id="wheel"), pytest.param(".", id="dir")]
)
def test_cli_validate(make_wheel: MakeWheel, tmp_path: Path, capsys: pytest.CaptureFixture[str], target: str) -> None:
    wheel: Final[Path] = make_wheel("License-Expression: MIT\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'native'\n", encoding="utf-8")
    main(["embed", str(wheel), "--root", str(tmp_path)])
    main(["validate", str(wheel.parent / target), "--allow-license", "MIT"])
    assert capsys.readouterr().out.splitlines()[-1] == "SBOM in native-1.0-py3-none-any.whl is valid"


def test_cli_validate_problems(make_wheel: MakeWheel, capsys: pytest.CaptureFixture[str]) -> None:
    wheel: Final[Path] = make_wheel("")
    with pytest.raises(SystemExit) as error:
        main(["validate", str(wheel)])
    assert (error.value.code, capsys.readouterr().err) == (
        1,
        "SBOM invalid: native-1.0-py3-none-any.whl: no .dist-info/sboms/*.cdx.json found in the wheel\n",
    )


def test_cli_validate_no_wheel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main(["validate", str(tmp_path)])
    assert (error.value.code, capsys.readouterr().err) == (1, f"no wheel found in {tmp_path}\n")


def test_cli_embed_not_a_wheel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with zipfile.ZipFile(archive := tmp_path / "broken-1.0-py3-none-any.whl", "w") as zipped:
        zipped.writestr("broken/__init__.py", "")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'broken'\n", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        main(["embed", str(archive), "--root", str(tmp_path)])
    assert (error.value.code, capsys.readouterr().err) == (
        1,
        f"python-sbom embed: {archive} has no .dist-info/METADATA, so it is not a wheel\n",
    )
