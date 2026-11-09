"""Build an archive's SBOM, write it beside the archive or to a given file, and optionally append it to the archive."""

from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom._collect._archive import read_archive
from python_sbom._collect._content import resolve_provider
from python_sbom._collect._facts import collect_facts
from python_sbom._collect._revision import revision_reader
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._source import copyright_notice, hash_build_scripts
from python_sbom._errors import SbomError
from python_sbom._formats._json import dumps
from python_sbom._model._archive import archive_artifact, bundled_paths
from python_sbom._model._bom import assemble, checked_contributions
from python_sbom._model._content import ProviderContext
from python_sbom._model._identity import project_identity
from python_sbom._model._names import archive_sbom_file_name
from python_sbom._wheel._reader import open_artifact
from python_sbom._wheel._write import append_member

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path, PurePosixPath

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._inputs import BuildFacts
    from python_sbom._model._types import Document


def archive_sbom(  # ruff: ignore[too-many-arguments] # every command-line option reaches the build
    root: Path,
    archive: Path,
    *,
    provider: ContentProvider | str | None,
    commit: str | None,
    build_env: Sequence[str] | None,
    build_scripts: Sequence[PurePosixPath],
    output: Path | None,
    embed: bool,
) -> tuple[Path, str | None]:
    name = archive_sbom_file_name(archive.name)
    if (target := output or archive.with_name(name)).exists() and target.samefile(archive):
        msg = f"{target} is the archive {archive} itself, refusing to overwrite it with the SBOM"
        raise SbomError(msg)
    facts = collect_facts(root, revision_reader(commit), path=build_env)
    document = describe_archive(root, archive, facts=facts, provider=provider, build_scripts=build_scripts)
    target.write_bytes(content := dumps(document))
    if not embed:
        return target, None
    append_member(archive, name, content, facts.epoch)
    return target, name


def describe_archive(
    root: Path,
    archive: Path,
    *,
    facts: BuildFacts,
    provider: ContentProvider | str | None,
    build_scripts: Sequence[PurePosixPath],
) -> Document:
    settings = settings_from_pyproject(root)
    content, provider_scripts = resolve_provider(provider, settings, root)
    with open_artifact(archive) as artifact:
        tree = read_archive(artifact)
        project = project_identity(tree.metadata[""], settings)
        context = ProviderContext(root=root, settings=settings, identity=project, read=artifact.provider_read)
        built = archive_artifact(
            archive.name,
            tree,
            project=project,
            bundled_info={str(path): content.bundled_wheel(context, path) for path in bundled_paths(tree)},
            build_scripts=hash_build_scripts(root, [*build_scripts, *provider_scripts]),
            copyright_line=copyright_notice(root, tree.metadata[""].values("license_files")),
        )
        contributions = checked_contributions(content.contributions(context), content)
    return assemble(built, project, settings, facts, contributions)


__all__ = [
    "archive_sbom",
    "describe_archive",
]
