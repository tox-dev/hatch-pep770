from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from python_sbom import _core
from python_sbom._collect._content import load_content_provider, provider_script
from python_sbom._collect._facts import collect_facts, commit_revision, default_revision
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._source import read_source_tree, wheel_request
from python_sbom._model._content import ProviderContext
from python_sbom._model._identity import project_identity
from python_sbom._wheel._archive import write_sbom

from ._pipeline import build_sbom

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from python_sbom._collect._facts import RevisionReader
    from python_sbom._model._content import ContentProvider
    from python_sbom._model._inputs import BuildFacts, SbomRequest


def embed_sbom(
    wheel: Path,
    root: Path,
    *,
    content: ContentProvider | None,
    commit: str | None = None,
    build_env: Sequence[str] | None,
) -> str:
    settings = settings_from_pyproject(root, {})
    content = content or load_content_provider(settings.content_provider, root)
    scripts = tuple(filter(None, [provider_script(content, root)]))
    return embed_into(
        wheel,
        wheel_request(wheel, root, settings, scripts),
        content,
        collect_facts(root, revision_reader(commit), path=build_env),
    )


def embed_into(wheel: Path, request: SbomRequest, content: ContentProvider, facts: BuildFacts) -> str:
    source = read_source_tree(request)
    inside = dict(_core.whl_member_digests(wheel))
    # a bundled wheel the built wheel holds is named by its path in there, as an archive SBOM names it, so both
    # documents give one wheel the same identity
    source = dataclasses.replace(
        source,
        bundled=[
            dataclasses.replace(bundled, path=inside.get(bundled.sha256, bundled.path)) for bundled in source.bundled
        ],
    )
    project = project_identity(request.metadata, request.settings)
    context = ProviderContext(root=request.root, settings=request.settings, identity=project, artifact=wheel)
    sbom = build_sbom(request, source, facts, content, context)
    return write_sbom(wheel, sbom.file_name, sbom.content, facts.epoch)


def revision_reader(commit: str | None) -> RevisionReader:
    if commit is None:
        return default_revision
    revision = commit_revision(commit, "--commit")
    return lambda _root: revision


__all__ = [
    "embed_into",
    "embed_sbom",
    "revision_reader",
]
