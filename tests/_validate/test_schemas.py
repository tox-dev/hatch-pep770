from __future__ import annotations

import json
import sys

import pytest

from python_sbom._errors import MissingExtraError
from python_sbom._validate._document import validate_document
from python_sbom._validate._schemas import schema_error


def test_validate_without_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    # None in sys.modules makes the import fail, as when the extra is not installed
    monkeypatch.setitem(sys.modules, "cyclonedx.schema", None)
    monkeypatch.delitem(sys.modules, "python_sbom._validate._schemas", raising=False)
    with pytest.raises(MissingExtraError, match=r"pip install 'python-sbom\[validate\]'"):
        validate_document("{}", None)


def test_schema_error_names_the_path() -> None:
    raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "one"})
    assert schema_error(raw) == "'one' is not of type 'integer' at $.version"


def test_schema_error_clips_the_offending_value() -> None:
    raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "x" * 1000})
    assert schema_error(raw) == f"'{'x' * 199} at $.version"
