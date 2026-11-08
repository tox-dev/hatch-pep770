from __future__ import annotations

from packaging.version import Version

from python_sbom import __version__


def test_version() -> None:
    assert Version(__version__).release
