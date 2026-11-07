from __future__ import annotations

import json

from python_sbom._validate._schemas import schema_error


def test_schema_error_names_the_path() -> None:
    raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "one"})
    assert schema_error(raw) == "'one' is not of type 'integer' at $.version"


def test_schema_error_clips_the_offending_value() -> None:
    raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "x" * 1000})
    assert schema_error(raw) == f"'{'x' * 199} at $.version"
