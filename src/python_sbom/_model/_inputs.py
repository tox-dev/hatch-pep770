from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import PurePosixPath

    from ._metadata import CoreMetadata
    from ._types import Component, Dependency, OrganizationalEntity


@dataclass(frozen=True, slots=True, kw_only=True)
class RecordRow:
    path: str
    algorithm: str
    digest: str
    size: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Interpreter:
    name: str
    version: str
    implementation: str


@dataclass(frozen=True, slots=True, kw_only=True)
class InstalledDistribution:
    name: str
    metadata: CoreMetadata
    files: list[RecordRow]
    depends_on: list[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class Revision:
    commit: str
    dirty: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class BuildFacts:
    epoch: int
    epoch_from_environment: bool
    revision: Revision | None
    interpreter: Interpreter
    distributions: list[InstalledDistribution]


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    """
    The project's options, from ``[tool.python-sbom]``.

    :param supplier: the organization that supplies the project, or ``None`` to name none
    :param repository: the repository URL, or ``None`` to take the first ``Source``, ``Repository`` or ``GitHub``
        project URL
    :param default_branch: the branch in links to files in the repository when the build's commit is unknown or has
        uncommitted changes
    :param bundled_wheels: glob patterns, relative to the project directory, of wheels the project ships as data files
    :param content_provider: ``module:attribute`` of the content provider, or ``None``
    :param build_backend: the build backend :mod:`python_sbom.backend` wraps, as ``module`` or ``module:object``, or
        ``None``

    """

    supplier: OrganizationalEntity | None
    repository: str | None
    default_branch: str
    bundled_wheels: tuple[str, ...]
    content_provider: str | None
    build_backend: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class BundledWheel:
    path: str
    sha256: str
    metadata_name: str
    metadata: CoreMetadata
    files: list[RecordRow]
    vendored: list[tuple[str, CoreMetadata]]


@dataclass(frozen=True, slots=True, kw_only=True)
class BuildScript:
    path: PurePosixPath
    sha256: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ArchiveTree:
    # what an archive holds, read from the zip without unpacking it: each distribution's metadata and members by the
    # directory that holds its .dist-info, "" for the project's own, the archive's own top-level files, the digest of
    # every member but the bundled wheels, and those wheels
    metadata: dict[str, CoreMetadata]
    owned: dict[str, list[str]]
    loose: list[str]
    files: dict[str, RecordRow]
    bundled: dict[str, BundledWheel]


@dataclass(frozen=True, slots=True, kw_only=True)
class Artifact:
    # what one artifact, a wheel or an archive, puts in its SBOM; the provenance every artifact of the project shares is
    # added around it
    root: Component
    components: list[Component]
    dependencies: list[Dependency]
    build_scripts: list[BuildScript]
    version: str
    sbom_file: str
    scope: str
    workflow: tuple[str, str]
    license_file: str | None
    copyright: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class WheelTree:
    # what a built wheel holds, read from the wheel without unpacking it: its file name, its core metadata and the
    # wheels it bundles; and what the project adds: the copyright line of its license files and the scripts that built
    # it
    name: str
    metadata: CoreMetadata
    copyright: str | None
    bundled: list[BundledWheel]
    build_scripts: list[BuildScript]


__all__ = [
    "ArchiveTree",
    "Artifact",
    "BuildFacts",
    "BuildScript",
    "BundledWheel",
    "InstalledDistribution",
    "Interpreter",
    "RecordRow",
    "Revision",
    "Settings",
    "WheelTree",
]
