from __future__ import annotations

import json
from typing import TYPE_CHECKING, Protocol

from python_sbom._errors import SbomError
from python_sbom._formats._spdx import to_spdx
from python_sbom._validate._document import is_document

if TYPE_CHECKING:
    from pathlib import Path


class _Options(Protocol):
    source: Path
    target: Path


def run(options: _Options) -> bool:
    if not is_document(loaded := json.loads(options.source.read_text(encoding="utf-8"))):
        msg = f"{options.source} is not a CycloneDX document python-sbom can render"
        raise SbomError(msg)
    try:
        rendered = to_spdx(loaded)
    except (KeyError, TypeError) as error:
        # the CLI renders without the schema check, which needs the validate extra
        msg = f"{options.source} is not a CycloneDX document python-sbom can render: {error!r}"
        raise SbomError(msg) from error
    # bytes, so the line endings are the same on every operating system
    options.target.write_bytes(rendered.encode())
    return True


__all__ = [
    "run",  # simplint: ignore[SMP402] # the parser names it for pkgutil.resolve_name
]
