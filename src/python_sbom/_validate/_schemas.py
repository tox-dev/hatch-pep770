from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    from python_sbom._formats._spdx import Spdx


def schema_error(raw: str) -> str | None:
    return _core.schema_error(raw)


def spdx_problems(spdx: Spdx) -> list[str]:
    return _core.spdx_problems(spdx)


__all__ = [
    "schema_error",
    "spdx_problems",
]
