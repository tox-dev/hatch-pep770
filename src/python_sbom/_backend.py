from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from packaging.utils import canonicalize_name

from ._collect._source import read_source_tree
from ._formats._json import dumps
from ._model._wheel import WheelInputs, describe

if TYPE_CHECKING:
    from email.message import Message
    from pathlib import Path, PurePosixPath

    from ._collect._facts import BuildFacts
    from ._collect._settings import Settings
    from ._model._types import Property


class Backend(ABC):
    """
    Adapts a build system to the core: it supplies the wheel's metadata and the project's settings.

    The hatchling hook and :class:`BuiltWheel` are the two backends shipped; another build system adds a subclass.
    :meth:`sbom` reads the project tree, builds the document and serializes it.

    """

    def bundled_wheel_properties(self, wheel: Path) -> list[Property]:  # ruff: ignore[no-self-use]  # extension seam
        """
        Return extra properties for a wheel the project bundles as a data file; none by default.

        :param wheel: the bundled wheel, an absolute path under :attr:`root`
        :returns: the properties to add after ``<project>:bundled-wheel``

        """
        del wheel
        return []

    def sbom(self, facts: BuildFacts) -> tuple[str, bytes]:
        """
        Build the SBOM of the wheel.

        :param facts: what the environment says about the build, collected once per build
        :returns: the SBOM's file name under ``.dist-info/sboms/`` and its JSON

        """
        metadata = self.metadata()
        source = read_source_tree(
            self.root, self.settings, metadata.get_all("License-File", []), self.build_script(), self
        )
        inputs = WheelInputs(
            metadata=metadata, wheel_name=self.wheel_name(), settings=self.settings, facts=facts, source=source
        )
        return f"{canonicalize_name(metadata['Name'])}.cdx.json", dumps(describe(inputs))

    @abstractmethod
    def metadata(self) -> Message:
        """
        Return the core metadata of the wheel.

        :returns: the parsed ``METADATA``

        """

    @property
    @abstractmethod
    def root(self) -> Path:
        """The project directory."""

    @property
    @abstractmethod
    def settings(self) -> Settings:
        """The project's options."""

    def build_script(self) -> PurePosixPath | None:  # ruff: ignore[no-self-use]  # backends override it
        """
        Return a build script to list among the build tools, as hatchling's custom hook script.

        :returns: the script, relative to :attr:`root`, or ``None``, the default, for none

        """
        return None

    @abstractmethod
    def wheel_name(self) -> str:
        """
        Return the file name of the wheel, for its attestation link.

        :returns: the file name

        """


__all__ = [
    "Backend",
]
