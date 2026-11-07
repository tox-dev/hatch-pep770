from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path, PurePosixPath

    from ._metadata import CoreMetadata
    from ._types import Component, Dependency, OrganizationalEntity, Property


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
    :param default_branch: the branch in links to files in the repository
    :param bundled_wheels: glob patterns, relative to the project directory, of wheels the project ships as data files
    :param content_provider: ``module:attribute`` of the content provider, or ``None``

    """

    supplier: OrganizationalEntity | None
    repository: str | None
    default_branch: str
    bundled_wheels: tuple[str, ...]
    content_provider: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class SbomRequest:
    root: Path
    metadata: CoreMetadata
    wheel_name: str
    settings: Settings
    build_scripts: tuple[PurePosixPath, ...]


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
class SourceTree:
    copyright: str | None
    bundled: list[BundledWheel]
    build_scripts: list[BuildScript]


@dataclass(frozen=True, slots=True, kw_only=True)
class BundledWheelInfo:
    """
    What a project adds to the component of one bundled wheel.

    Both fields default to empty, so a provider names only what it adds.

    :param properties: properties after ``<prefix>:bundled-wheel``, before those from the wheel's metadata
    :param supplier: the wheel's supplier, or ``None`` to name none; only the project decides a bundled wheel's
        supplier, never the wheel's own metadata

    """

    properties: list[Property] = field(default_factory=list)
    supplier: OrganizationalEntity | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Contributions:
    """
    What a project adds to the document beyond its bundled wheels, merged before references and the serial are derived.

    Each field defaults to empty, so a provider names only what it adds. The build fails when a component or tool lacks
    ``type``, ``bom-ref`` or ``name``, a ``bom-ref`` repeats, the ``formula:`` and ``workflow:`` refs of the build's
    formulation included, a dependency names one that does not exist, or a ``bom-ref`` gets a second dependency entry,
    as the root does if a provider adds one, since python-sbom writes the root's.

    :param components: extra top-level components, such as vendored C libraries; the root depends on each, and a
        component's own parts nest under its ``components``
    :param dependencies: extra dependency entries, such as the dependencies of those components
    :param root_properties: extra properties of the root component; their names must not start with the project's
        prefix, which python-sbom's own properties use
    :param tools: extra build tools

    """

    components: list[Component] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    root_properties: list[Property] = field(default_factory=list)
    tools: list[Component] = field(default_factory=list)


__all__ = [
    "Artifact",
    "BuildFacts",
    "BuildScript",
    "BundledWheel",
    "BundledWheelInfo",
    "Contributions",
    "InstalledDistribution",
    "Interpreter",
    "RecordRow",
    "Revision",
    "SbomRequest",
    "Settings",
    "SourceTree",
]
