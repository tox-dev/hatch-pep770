from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from python_sbom._collect._archive import member_reader
from python_sbom._collect._content import resolve_provider
from python_sbom._collect._facts import collect_facts
from python_sbom._collect._revision import revision_reader
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._source import read_source_tree, wheel_request
from python_sbom._formats._json import dumps
from python_sbom._model._bom import describe
from python_sbom._model._content import ProviderContext
from python_sbom._model._document import checked_contributions
from python_sbom._model._identity import project_identity
from python_sbom._model._names import sbom_file_name
from python_sbom._wheel._archive import bundled_wheels_by_digest, write_sbom

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._inputs import BuildFacts, SbomRequest, SourceTree
    from python_sbom._model._types import Document


def embed_sbom(
    wheel: Path,
    root: Path,
    *,
    provider: ContentProvider | str | None,
    commit: str | None,
    build_env: Sequence[str] | None,
) -> str:
    settings = settings_from_pyproject(root)
    content, scripts = resolve_provider(provider, settings, root)
    return embed_into(
        wheel,
        wheel_request(wheel, root, settings, scripts),
        content,
        collect_facts(root, revision_reader(commit), path=build_env),
    )


def embed_into(wheel: Path, request: SbomRequest, content: ContentProvider, facts: BuildFacts) -> str:
    source = read_source_tree(request, inside=bundled_wheels_by_digest(wheel))
    project = project_identity(request.metadata, request.settings)
    context = ProviderContext(root=request.root, settings=request.settings, identity=project, read=member_reader(wheel))
    sbom = build_sbom(request, source, facts, content, context)
    return write_sbom(wheel, sbom.file_name, sbom.content, facts.epoch)


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
            checked_contributions(content.contributions(context), content),
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
    "embed_into",
    "embed_sbom",
]
