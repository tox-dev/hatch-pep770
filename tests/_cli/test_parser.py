from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from python_sbom._cli._parser import build_parser

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    "value",
    [pytest.param("0", id="zero"), pytest.param("-1", id="negative"), pytest.param("many", id="not-a-number")],
)
def test_max_components_must_be_positive(value: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["validate", str(tmp_path), "--max-components", value])
    assert (exit_info.value.code, capsys.readouterr().err.splitlines()[-1]) == (
        2,
        f"python-sbom validate: error: argument --max-components: must be a positive integer, got {value!r}",
    )


def test_max_components_takes_positive(tmp_path: Path) -> None:
    assert build_parser().parse_args(["validate", str(tmp_path), "--max-components", "1"]).max_components == 1
