from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from python_sbom._formats._json import dumps
from python_sbom._model._bom import describe
from python_sbom._model._names import sbom_file_name

if TYPE_CHECKING:
    from python_sbom._model._content import ContentProvider, ProviderContext
    from python_sbom._model._inputs import BuildFacts, SbomRequest, SourceTree
    from python_sbom._model._types import Document


def build_sbom(
    request: SbomRequest, source: SourceTree, facts: BuildFacts, content: ContentProvider, context: ProviderContext
) -> Sbom:
    return Sbom(
        file_name=sbom_file_name(request.metadata.name),
        document=describe(
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
    document: Document

    @property
    def content(self) -> bytes:
        return dumps(self.document)


__all__ = [
    "Sbom",
    "build_sbom",
]
