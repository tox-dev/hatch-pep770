from __future__ import annotations

from typing import TYPE_CHECKING

from ._inputs import BundledWheelInfo, Contributions

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path, PurePosixPath

    from ._identity import ProjectIdentity
    from ._inputs import Settings


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

    def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:  # ruff: ignore[unused-method-argument, no-self-use] # the no-op default
        """
        Describe what the project does with a wheel it bundles, as a file or unpacked into a directory.

        :param context: the project and the artifact being described
        :param wheel: the wheel's path inside the artifact
        :returns: its extra properties, and whether the project's supplier supplies it; neither by default

        """
        return BundledWheelInfo()

    def contributions(self, context: ProviderContext) -> Contributions:  # ruff: ignore[unused-method-argument, no-self-use] # the no-op default
        """
        Add components, their dependencies, root properties and build tools, before references and the serial derive.

        :param context: the project and the artifact being described
        :returns: the contributions; none by default

        """
        return Contributions()


__all__ = [
    "ContentProvider",
    "ProviderContext",
]
