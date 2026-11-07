from __future__ import annotations

import dataclasses
import json
import uuid
from email import message_from_string
from typing import TYPE_CHECKING

import pytest

from python_sbom import ProjectIdentity, document, project_identity

if TYPE_CHECKING:
    from python_sbom import Body, Settings


@pytest.mark.parametrize(
    ("repository", "urls", "expected"),
    [
        pytest.param(None, "", None, id="none"),
        pytest.param(
            None,
            "Project-URL: Docs, https://example.org\nProject-URL: Source, https://github.com/example/example/\n",
            "https://github.com/example/example",
            id="first-vcs-project-url",
        ),
        pytest.param(
            "https://git.example.org/example",
            "Project-URL: Source, https://github.com/example/example\n",
            "https://git.example.org/example",
            id="setting-wins",
        ),
    ],
)
def test_project_identity_repository(
    settings: Settings, repository: str | None, urls: str, expected: str | None
) -> None:
    metadata = message_from_string(f"Name: My_Project\nVersion: 1.0\n{urls}")
    identity = project_identity(metadata, dataclasses.replace(settings, repository=repository))
    assert identity == ProjectIdentity(
        namespace="my-project",
        repository=expected,
        serial_namespace=uuid.uuid5(uuid.NAMESPACE_URL, f"{expected or 'https://pypi.org/project/my-project'}/sboms"),
    )


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
    assert document(body, namespace) == {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, json.dumps(body, sort_keys=True))}",
        "version": 1,
        **body,
    }
