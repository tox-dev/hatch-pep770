from __future__ import annotations

import dataclasses
import uuid
from typing import TYPE_CHECKING

import pytest

from python_sbom._model._identity import ProjectIdentity, project_identity
from python_sbom._model._metadata import parse_metadata

if TYPE_CHECKING:
    from python_sbom._model._inputs import Settings


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
        pytest.param(
            None,
            "Project-URL: Source, git@github.com:example/example.git\n"
            "Project-URL: Repository, https://github.com/example/example\n",
            "https://github.com/example/example",
            id="scp-style-passed-over",
        ),
        pytest.param(
            None,
            "Project-URL: Source, https://git.example.org/{team}/example\n",
            "https://git.example.org/%7Bteam%7D/example",
            id="encoded",
        ),
    ],
)
def test_project_identity_repository(
    settings: Settings, repository: str | None, urls: str, expected: str | None
) -> None:
    metadata = parse_metadata(f"Name: My_Project\nVersion: 1.0\n{urls}")
    identity = project_identity(metadata, dataclasses.replace(settings, repository=repository))
    assert identity == ProjectIdentity(
        property_prefix="my-project",
        repository=expected,
        serial_namespace=uuid.uuid5(uuid.NAMESPACE_URL, f"{expected or 'https://pypi.org/project/my-project'}/sboms"),
    )
