from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from python_sbom._model._types import Document

    from ._spdx import Spdx


def dumps(document: Document | Spdx) -> bytes:
    # what f"{json.dumps(document, indent=2)}\n".encode() writes
    return _core.dumps(document)


__all__ = [
    "dumps",
]
