from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from email.message import Message
    from importlib.metadata import PackageMetadata

    from ._types import License


def licenses(metadata: PackageMetadata | Message | _core.Metadata) -> list[License]:
    # a License-Expression is taken as declared; otherwise each License field and License classifier name is
    # declared, and the SPDX ids they map to are added as concluded
    return _core.licenses(metadata)


__all__ = [
    "licenses",
]
