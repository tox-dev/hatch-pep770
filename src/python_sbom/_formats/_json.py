from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from python_sbom._model._types import Document

    from ._spdx import Spdx


def dumps(document: Document | Spdx) -> bytes:
    """
    Serialize a document the way python-sbom writes it: two-space indented JSON and a final newline.

    :param document: a CycloneDX or SPDX document
    :returns: UTF-8 bytes, with the same line endings on every operating system

    """
    return f"{json.dumps(document, indent=2)}\n".encode()


__all__ = [
    "dumps",
]
