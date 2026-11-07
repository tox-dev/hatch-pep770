from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from email.message import Message
    from pathlib import Path, PurePosixPath

    from ._types import Component, Dependency, OrganizationalEntity, Property


@dataclass(frozen=True, slots=True, kw_only=True)
class RecordRow:
    """
    One file of a wheel, as its ``RECORD`` lists it.

    :param path: the file's path inside the wheel
    :param algorithm: the hash algorithm as CycloneDX names it, such as ``SHA-256``
    :param digest: the file's digest as lowercase hex
    :param size: the file's size in bytes, as ``RECORD`` writes it

    """

    path: str
    algorithm: str
    digest: str
    size: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Interpreter:
    """
    The Python that runs the build.

    :param name: the implementation name, such as ``cpython``
    :param version: the full version, such as ``3.15.0``
    :param implementation: the implementation as :func:`platform.python_implementation` names it, such as ``CPython``

    """

    name: str
    version: str
    implementation: str


@dataclass(frozen=True, slots=True, kw_only=True)
class InstalledDistribution:
    """
    One distribution of the build environment.

    :param metadata: its core metadata
    :param files: its files, for a pure-Python distribution; empty for a platform one, whose files differ per machine
    :param depends_on: the normalized names of the installed distributions it requires in this environment

    """

    metadata: Message
    files: list[RecordRow]
    depends_on: list[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class Revision:
    """
    The source revision a build comes from.

    :param commit: the commit identifier
    :param dirty: whether tracked files differed from the commit when the build ran

    """

    commit: str
    dirty: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class BuildFacts:
    """
    What the environment says about the build, collected once per build at the edge.

    :param epoch: the build time as a Unix timestamp
    :param epoch_from_environment: whether ``SOURCE_DATE_EPOCH`` set the build time
    :param revision: the source revision, or ``None`` when it is unknown
    :param interpreter: the Python that runs the build
    :param distributions: every distribution of the build environment

    """

    epoch: int
    epoch_from_environment: bool
    revision: Revision | None
    interpreter: Interpreter
    distributions: list[InstalledDistribution]


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    """
    The options a project sets, in a hatchling hook's table or in ``[tool.python-sbom]``.

    :param supplier: the organization that supplies the project, or ``None`` to name none
    :param repository: the repository URL, or ``None`` to take the first ``Source``, ``Repository`` or ``GitHub``
        project URL
    :param default_branch: the branch in links to files in the repository
    :param bundled_wheels: glob patterns, relative to the project root, of wheels the project ships as data files
    :param content_provider: ``module:attribute`` of a content provider importable from the project root, or ``None``

    """

    supplier: OrganizationalEntity | None
    repository: str | None
    default_branch: str
    bundled_wheels: tuple[str, ...]
    content_provider: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class SbomRequest:
    """
    What a backend knows about the wheel it builds or rewrites.

    :param root: the project directory
    :param metadata: the wheel's core metadata
    :param wheel_name: the wheel's file name, for its attestation link
    :param settings: the project's options
    :param build_scripts: scripts, relative to ``root``, that shape the document, listed among the build tools

    """

    root: Path
    metadata: Message
    wheel_name: str
    settings: Settings
    build_scripts: tuple[PurePosixPath, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class BundledWheel:
    """
    A wheel the project ships as a data file.

    :param path: its path relative to the project root
    :param sha256: the SHA-256 of its bytes, as lowercase hex
    :param metadata_name: the path of its ``METADATA`` inside it
    :param metadata: its core metadata
    :param files: its files, from its ``RECORD``
    :param vendored: the packages it vendors, each with the file that names it

    """

    path: str
    sha256: str
    metadata_name: str
    metadata: Message
    files: list[RecordRow]
    vendored: list[tuple[str, Message]]


@dataclass(frozen=True, slots=True, kw_only=True)
class BuildScript:
    """
    A build script that shapes the document, so a rebuild has to match it.

    :param path: its path relative to the project root
    :param sha256: the SHA-256 of its bytes, as lowercase hex

    """

    path: PurePosixPath
    sha256: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceTree:
    """
    What the document takes from the project tree besides the wheel's metadata.

    :param copyright: the first ``Copyright`` line of the license files, or ``None``
    :param bundled: the wheels the project ships as data files
    :param build_scripts: the scripts that shape the document

    """

    copyright: str | None
    bundled: list[BundledWheel]
    build_scripts: list[BuildScript]


@dataclass(frozen=True, slots=True, kw_only=True)
class BundledWheelInfo:
    """
    What a project adds to the component of one bundled wheel.

    :param properties: properties after ``<project>:bundled-wheel``, before those from the wheel's metadata
    :param supplier: the wheel's supplier, or ``None`` to name none; only the project decides it, never the wheel

    """

    properties: list[Property]
    supplier: OrganizationalEntity | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Contributions:
    """
    What a project adds to the document beyond its bundled wheels, merged before references and the serial are derived.

    :param components: extra top-level components, such as vendored C libraries; the root depends on each
    :param dependencies: extra dependency entries, such as the dependencies of those components
    :param root_properties: extra properties of the root component
    :param tools: extra build tools

    """

    components: list[Component]
    dependencies: list[Dependency]
    root_properties: list[Property]
    tools: list[Component]


__all__ = [
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
