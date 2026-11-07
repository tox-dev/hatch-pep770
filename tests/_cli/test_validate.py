from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._cli._main import main

if TYPE_CHECKING:
    from pathlib import Path

    from tests.conftest import WriteWheel

_SBOM: Final[str] = "native-1.0.dist-info/sboms/native.cdx.json"


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
