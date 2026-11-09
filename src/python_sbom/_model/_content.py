"""The content provider interface, the context it reads and the contributions it returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path, PurePosixPath

    from ._identity import ProjectIdentity
    from ._inputs import Settings
    from ._types import Component, Dependency, OrganizationalEntity, Property


class ProviderContext:
    """
    What a content provider may use about the build it contributes to.

    :param root: the project directory
    :param settings: the project's options
    :param identity: how the project's SBOMs name it, including the prefix of its properties
    :param read: reads a member of the artifact being described, for :meth:`read`

    """

    def __init__(
        self, *, root: Path, settings: Settings, identity: ProjectIdentity, read: Callable[[PurePosixPath], bytes]
    ) -> None:
        self.root = root
        self.settings = settings
        self.identity = identity
        self._read = read

    def read(self, path: PurePosixPath) -> bytes:
        """
        Read a file of the artifact being described: a member of the built wheel or of the archive.

        :param path: the file's path inside the artifact, as a bundled wheel's path is given
        :returns: the file's bytes
        :raises KeyError: when the artifact holds no such file

        """
        return self._read(path)


class ContentProvider:
    """
    Adds what a project knows beyond its metadata to its SBOM; subclass it and override what the project needs.

    Name a subclass in the ``content-provider`` option, which the hook, ``python-sbom embed`` and ``python-sbom
    archive`` load, or return an instance from :meth:`python_sbom.hatch.SbomBuildHook.content_provider`. When the class
    lives in the project, the SBOM lists its module among the build tools.

    """

    # ruff: disable[unused-method-argument, no-self-use] # the defaults add nothing, whatever they are given
    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
        """
        Describe what the project does with a wheel it bundles, as a file or unpacked into a directory.

        :param context: the project and the artifact being described
        :param wheel: the wheel's path inside the artifact
        :returns: its extra properties, and whether the project's supplier supplies it; neither by default

        """
        return BundledWheelInfo()

    def contributions(self, context: ProviderContext) -> Contributions:
        """
        Add components, their dependencies, root properties and build tools, before references and the serial derive.

        :param context: the project and the artifact being described
        :returns: the contributions; none by default

        """
        return Contributions()

    # ruff: enable[unused-method-argument, no-self-use]


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
    "BundledWheelInfo",
    "ContentProvider",
    "Contributions",
    "ProviderContext",
]
