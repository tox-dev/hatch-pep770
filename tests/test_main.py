from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def test_main(capfd: pytest.CaptureFixture[str]) -> None:
    subprocess.check_call([sys.executable, "-m", "hatch_pep770", "-h"])
    out, _err = capfd.readouterr()
    assert out.startswith("usage: hatch-pep770 ")


def test_script(capfd: pytest.CaptureFixture[str]) -> None:
    subprocess.check_call([Path(sys.executable).parent / "hatch-pep770", "-h"])
    out, _err = capfd.readouterr()
    assert out.startswith("usage: hatch-pep770 ")
