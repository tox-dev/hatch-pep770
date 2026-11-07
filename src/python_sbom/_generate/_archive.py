from __future__ import annotations

import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from python_sbom import _core
from python_sbom._collect._content import load_content_provider, provider_script
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._model._content import ProviderContext
from python_sbom._model._identity import ProjectIdentity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from python_sbom._model._content import ContentProvider
    from python_sbom._model._inputs import BuildFacts
    from python_sbom._model._types import Document


def describe_archive(
    root: Path,
    archive: Path,
    *,
    facts: BuildFacts,
    content: ContentProvider | None = None,
    build_scripts: Sequence[PurePosixPath] = (),
) -> Document:
    return archive_document(root, archive, facts=facts, content=content, build_scripts=build_scripts).to_python()


def archive_document(
    root: Path,
    archive: Path,
    *,
    facts: BuildFacts,
    content: ContentProvider | None = None,
    build_scripts: Sequence[PurePosixPath] = (),
) -> _core.Document:
    # the archive's top-level .dist-info names the project; every other .dist-info marks a wheel bundled unpacked into
    # its parent directory and every .whl member a bundled wheel; other files belong to the deepest distribution that
    # holds them, or, at the top level, to the archive
    settings = settings_from_pyproject(root, {})
    content = content or load_content_provider(settings.content_provider, root)
    # unpacked, so a content provider reads the archive's files the way it reads the project's
    with tempfile.TemporaryDirectory() as directory:
        scan = _core.ArchiveScan(archive, Path(directory), settings)
        prefix, repository, namespace = scan.identity
        identity = ProjectIdentity(property_prefix=prefix, repository=repository, serial_namespace=uuid.UUID(namespace))
        context = ProviderContext(root=root, settings=settings, identity=identity, artifact=Path(directory))
        infos = [content.bundled_wheel(context, PurePosixPath(query)) for query in scan.queries]
        contributions = content.contributions(context)
    scripts = [*build_scripts, *filter(None, [provider_script(content, root)])]
    # str, so a Windows drive in an absolute path survives the join with the native root
    return scan.finish(infos, contributions, facts, [(str(path), root / str(path)) for path in scripts])


__all__ = [
    "archive_document",
    "describe_archive",
]
