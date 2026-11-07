from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

    from tests.conftest import WriteWheel


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
