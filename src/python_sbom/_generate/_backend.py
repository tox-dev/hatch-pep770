from __future__ import annotations

import zipfile
from abc import ABC, abstractmethod
from email.parser import Parser
from typing import TYPE_CHECKING

from python_sbom._errors import WheelError
from python_sbom._model._inputs import SbomRequest
from python_sbom._wheel._archive import find_dist_info, read_metadata_member

if TYPE_CHECKING:
    from pathlib import Path, PurePosixPath

    from python_sbom._model._inputs import Settings


class Backend(ABC):
    """Adapts a build system to python-sbom: it says what it knows about the wheel it builds or rewrites."""

    @abstractmethod
    def request(self) -> SbomRequest:
        """
        Describe the wheel.

        :returns: the project directory, the wheel's metadata and file name, the settings and the build scripts

        """


class MetadataBackend(Backend):
    """
    A backend for build systems that hand over the core metadata before the wheel exists, such as a build hook.

    :param root: the project directory
    :param metadata: the wheel's ``METADATA`` text
    :param wheel_name: the wheel's file name
    :param settings: the project's options
    :param build_scripts: scripts, relative to ``root``, that shape the document

    """

    def __init__(
        self,
        *,
        root: Path,
        metadata: str,
        wheel_name: str,
        settings: Settings,
        build_scripts: tuple[PurePosixPath, ...],
    ) -> None:
        self._request = SbomRequest(
            root=root,
            metadata=Parser().parsestr(metadata),
            wheel_name=wheel_name,
            settings=settings,
            build_scripts=build_scripts,
        )

    def request(self) -> SbomRequest:
        """
        Return the request built from the metadata.

        :returns: the request

        """
        return self._request


class BuiltWheel(Backend):
    """
    A wheel some build backend already built, such as meson-python, and the project it came from.

    :param wheel: the built wheel file
    :param root: the project directory the wheel was built from
    :param settings: the project's options
    :param build_scripts: scripts, relative to ``root``, that shape the document

    """

    def __init__(
        self, *, wheel: Path, root: Path, settings: Settings, build_scripts: tuple[PurePosixPath, ...]
    ) -> None:
        self._wheel = wheel
        self._root = root
        self._settings = settings
        self._build_scripts = build_scripts

    def request(self) -> SbomRequest:
        """
        Read the wheel's core metadata.

        :returns: the request
        :raises WheelError: when the archive is not a wheel

        """
        with zipfile.ZipFile(self._wheel) as archive:
            if (dist_info := find_dist_info(archive.namelist())) is None:
                msg = f"{self._wheel} has no .dist-info/METADATA, so it is not a wheel"
                raise WheelError(msg)
            metadata = read_metadata_member(archive, f"{dist_info}/METADATA", str(self._wheel)).decode("utf-8")
        return SbomRequest(
            root=self._root,
            metadata=Parser().parsestr(metadata),
            wheel_name=self._wheel.name,
            settings=self._settings,
            build_scripts=self._build_scripts,
        )


__all__ = [
    "Backend",
    "BuiltWheel",
    "MetadataBackend",
]
