from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from python_sbom._formats._json import dumps
from python_sbom._model._bom import describe
from python_sbom._model._components import sbom_file_name

if TYPE_CHECKING:
    from python_sbom._model._inputs import BuildFacts, SbomRequest, SourceTree
    from python_sbom._model._types import Document

    from ._content import ContentProvider


def build_sbom(request: SbomRequest, source: SourceTree, facts: BuildFacts, content: ContentProvider) -> Sbom:
    """
    Build the SBOM of a wheel from what the edge gathered.

    :param request: what the backend knows about the wheel, from :meth:`Backend.request`
    :param source: the project tree, from :func:`read_source_tree`
    :param facts: the build facts, from :func:`collect_facts`
    :param content: what the project adds
    :returns: the SBOM

    """
    return Sbom(
        file_name=sbom_file_name(request.metadata["Name"]),
        document=describe(
            request,
            source,
            facts,
            {wheel.path: content.bundled_wheel(wheel) for wheel in source.bundled},
            content.contributions(request),
        ),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class Sbom:
    """
    An SBOM ready to write.

    :param file_name: its file name under ``.dist-info/sboms/``
    :param document: the CycloneDX document

    """

    file_name: str
    document: Document

    @property
    def content(self) -> bytes:
        """The document as python-sbom writes it: indented JSON with a final newline."""
        return dumps(self.document)


__all__ = [
    "Sbom",
    "build_sbom",
]
