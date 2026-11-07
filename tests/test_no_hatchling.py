from __future__ import annotations

import subprocess
import sys


def test_core_imports_without_hatchling() -> None:
    # None in sys.modules makes the import fail, as when hatchling is not installed
    code = (
        "import sys; sys.modules['hatchling'] = None\n"
        "import python_sbom\n"
        "try:\n    import python_sbom.hatch\nexcept ImportError:\n    print('core only')\n"
    )
    assert subprocess.check_output([sys.executable, "-c", code], text=True) == "core only\n"
