from __future__ import annotations

from email import message_from_string
from pathlib import Path
from typing import TYPE_CHECKING

from python_sbom import ContentProvider
from python_sbom._formats._json import dumps
from python_sbom._generate._pipeline import build_sbom
from python_sbom._model._inputs import SbomRequest, SourceTree

if TYPE_CHECKING:
    from conftest import ContextFor

    from python_sbom._model._inputs import BuildFacts, Settings


def test_sbom_file_name_and_content(settings: Settings, facts: BuildFacts, context_for: ContextFor) -> None:
    request = SbomRequest(
        root=Path(),
        metadata=message_from_string("Name: My.Project\nVersion: 1.0\n"),
        wheel_name="my_project-1.0-py3-none-any.whl",
        settings=settings,
        build_scripts=(),
    )
    context = context_for(Path(), Path())
    sbom = build_sbom(
        request, SourceTree(copyright=None, bundled=[], build_scripts=[]), facts, ContentProvider(), context
    )
    assert (sbom.file_name, sbom.content) == ("my-project.cdx.json", dumps(sbom.document))
