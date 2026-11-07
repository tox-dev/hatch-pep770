from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from python_sbom._model._content import ContentProvider, ProviderContext
    from python_sbom._model._inputs import BuildFacts, SbomRequest, SourceTree
    from python_sbom._model._types import Document


def build_sbom(
    request: SbomRequest, source: SourceTree, facts: BuildFacts, content: ContentProvider, context: ProviderContext
) -> Sbom:
    return Sbom(
        file_name=f"{_core.project_identity(request.metadata, request.settings)[0]}.cdx.json",
        built=_core.describe(
            request,
            source,
            facts,
            {wheel.path: content.bundled_wheel(context, PurePosixPath(wheel.path)) for wheel in source.bundled},
            content.contributions(context),
        ),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class Sbom:
    file_name: str
    #: the document as the core built it, written without becoming Python objects
    built: _core.Document

    @property
    def document(self) -> Document:
        return self.built.to_python()

    @property
    def content(self) -> bytes:
        return self.built.dumps()


__all__ = [
    "Sbom",
    "build_sbom",
]
