from __future__ import annotations

import sys

import pytest

from python_sbom import MissingExtraError, validate


def test_validate_without_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    # None in sys.modules makes the import fail, as when the extra is not installed
    monkeypatch.setitem(sys.modules, "cyclonedx.schema", None)
    monkeypatch.delitem(sys.modules, "python_sbom._validate._schemas", raising=False)
    with pytest.raises(MissingExtraError, match=r"pip install 'python-sbom\[validate\]'"):
        validate("{}", None)
