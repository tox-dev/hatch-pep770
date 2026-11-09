from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from python_sbom._collect._content import resolve_provider
from python_sbom._collect._facts import collect_facts
from python_sbom._collect._revision import revision_reader
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._wheel import read_wheel
from python_sbom._formats._json import dumps
from python_sbom._model._bom import assemble
from python_sbom._model._content import ProviderContext
from python_sbom._model._document import checked_contributions
from python_sbom._model._identity import project_identity
from python_sbom._model._wheel import wheel_artifact
from python_sbom._wheel._reader import open_artifact
from python_sbom._wheel._write import write_sbom

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._inputs import BuildFacts, Revision, Settings


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
    facts = collect_facts(root, revision_reader(commit), path=build_env)
    return embed_into(wheel, root, settings=settings, content=content, build_scripts=scripts, facts=facts)


def embed_into(  # ruff: ignore[too-many-arguments] # what the hook and the command line each gather their own way
    wheel: Path,
    root: Path,
    *,
    settings: Settings,
    content: ContentProvider,
    build_scripts: Sequence[PurePosixPath],
    facts: BuildFacts,
) -> str:
    # the wheel stays open while its document is built, for its metadata, its bundled wheels and the provider to read,
    # and is closed before it is rewritten
    with open_artifact(wheel) as artifact:
        tree = read_wheel(artifact, root, settings, build_scripts)
        project = project_identity(tree.metadata, settings)
        context = ProviderContext(root=root, settings=settings, identity=project, read=artifact.provider_read)
        built = wheel_artifact(
            tree,
            project=project,
            settings=settings,
            bundled_info={
                bundled.path: content.bundled_wheel(context, PurePosixPath(bundled.path)) for bundled in tree.bundled
            },
        )
        contributions = checked_contributions(content.contributions(context), content)
    return write_sbom(
        wheel, built.sbom_file, dumps(assemble(built, project, settings, facts, contributions)), facts.epoch
    )


def embed_built(wheel: Path, root: Path, revision: Revision | None, *, default_epoch: int | None = None) -> str:
    # a backend plugin reads the revision before the build writes into the checkout, which could make it look dirty,
    # and runs in the build's own environment, so the SBOM records the tools that built the wheel
    settings = settings_from_pyproject(root)
    content, scripts = resolve_provider(None, settings, root)
    facts = collect_facts(root, lambda _root: revision, default_epoch=default_epoch)
    return embed_into(wheel, root, settings=settings, content=content, build_scripts=scripts, facts=facts)


__all__ = [
    "embed_built",
    "embed_into",
    "embed_sbom",
]
