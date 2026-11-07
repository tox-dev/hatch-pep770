from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from python_sbom._model._types import Document

    from ._spdx import Spdx


def dumps(document: Document | Spdx) -> bytes:
    return f"{json.dumps(document, indent=2)}\n".encode()


__all__ = [
    "dumps",
]
