from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

import pytest

from python_sbom._errors import SbomError
from python_sbom._model._document import contributed_properties, with_header

if TYPE_CHECKING:
    from python_sbom import Property
    from python_sbom._model._types import Body


def test_document_serial_derives_from_body() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [],
    }
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "https://example.org/sboms")
    assert with_header(body, namespace) == {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }


def test_header_refuses_repeated_refs() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "bom-ref": "app", "name": "tool"}]},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [],
    }
    with pytest.raises(SbomError, match="bom-ref values repeat: app"):
        with_header(body, uuid.uuid4())


def test_header_refuses_unknown_dependency() -> None:
    body: Body = {
        "metadata": {
            "timestamp": "2023-11-14T22:13:20+00:00",
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": []},
            "component": {"type": "application", "bom-ref": "app", "name": "app"},
        },
        "components": [],
        "dependencies": [{"ref": "app", "dependsOn": ["ghost"]}],
    }
    with pytest.raises(SbomError, match="dependencies name bom-refs no component has: ghost"):
        with_header(body, uuid.uuid4())


def test_contributed_properties_keep_their_own_prefix() -> None:
    properties: list[Property] = [{"name": "extra:key", "value": "1"}]
    assert contributed_properties(properties, "example") == properties


def test_contributed_properties_refuse_the_project_prefix() -> None:
    with pytest.raises(SbomError, match="example:vcs-commit use the example: prefix python-sbom writes"):
        contributed_properties([{"name": "example:vcs-commit", "value": "0"}], "example")
