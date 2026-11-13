from __future__ import annotations

import subprocess
import sys


def test_backend_wildcard_import() -> None:
    code = (
        "from collections.abc import Mapping\n"
        "from python_sbom.backend import *\n"
        "assert ConfigSettings == Mapping[str, str | list[str]] | None\n"
        "assert callable(build_sdist) and callable(build_wheel)\n"
        "print('imported')\n"
    )
    assert subprocess.check_output([sys.executable, "-c", code], text=True) == "imported\n"
