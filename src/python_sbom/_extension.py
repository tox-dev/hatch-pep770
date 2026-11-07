from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pathlib import Path

    from ._model._types import Property


class ContentProvider(Protocol):
    """Adds project-specific content to the SBOM; the hatchling hook and every backend implement it."""

    def bundled_wheel_properties(self, wheel: Path) -> list[Property]:
        """
        Return extra properties for a wheel the project bundles as a data file.

        The properties follow ``<project>:bundled-wheel`` and precede the ones taken from the wheel's metadata.

        :param wheel: the bundled wheel, an absolute path under the project root
        :returns: the properties to add

        """
        ...


__all__ = [
    "ContentProvider",
]
