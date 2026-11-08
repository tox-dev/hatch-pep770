from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from python_sbom._cli._main import main
from python_sbom.version import __version__


def test_error_without_traceback(tmp_path: Path, wheel: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["embed", str(wheel), "--root", str(tmp_path)])
    assert exit_info.value.code == 1
    assert capsys.readouterr().err == f"python-sbom: {tmp_path} has no pyproject.toml to read [tool.python-sbom] from\n"


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["python-sbom", "--help"])
    with pytest.raises(SystemExit):
        runpy.run_module("python_sbom", run_name="__main__")
    assert capsys.readouterr().out.startswith("usage: python-sbom ")


def test_console_script() -> None:
    script = Path(sys.executable).parent / "python-sbom"
    assert subprocess.check_output([script, "--help"], text=True).startswith("usage: python-sbom ")


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out == f"python-sbom {__version__}\n"


@pytest.mark.parametrize(
    "arguments", [pytest.param("--version", id="version"), pytest.param("embed --help", id="help")]
)
def test_parsing_loads_no_command(arguments: str) -> None:
    code = (
        "import sys\nfrom python_sbom._cli._main import main\ntry:\n"
        f"    main({arguments.split()!r})\nexcept SystemExit:\n"
        "    print(sorted(name for name in sys.modules if name.startswith('python_sbom._cli.')))\n"
    )
    loaded = subprocess.check_output([sys.executable, "-c", code], text=True).splitlines()[-1]
    assert loaded == "['python_sbom._cli._main', 'python_sbom._cli._parser']"
