from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from python_sbom import SbomError
from python_sbom._formats._json import dumps, is_document, load_json
from python_sbom._formats._spdx import render_spdx
from python_sbom._validate._limits import MAX_COMPONENTS, byte_limit

if TYPE_CHECKING:
    from pathlib import Path

    from python_sbom._model._types import Document


class _Options(Protocol):
    source: Path
    target: Path


def run(options: _Options) -> bool:
    document = _read(options.source)
    try:
        rendered = dumps(render_spdx(document))
    # ValueError: a timestamp fromisoformat rejects; AttributeError: a tools value that is neither an array nor an
    # object; RecursionError: nesting json.dumps, a few frames deeper than json.loads, gives up on
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as error:
        # the CLI renders without the schema check, which needs the validate extra
        msg = f"{options.source} is not a CycloneDX document python-sbom can render: {error!r}"
        raise SbomError(msg) from error
    # bytes, so the line endings are the same on every operating system
    options.target.write_bytes(rendered)
    return True


def _read(source: Path) -> Document:
    # the size validate accepts at its default component cap, so the parser never holds more than validate lets it
    limit = byte_limit(MAX_COMPONENTS)
    try:
        with source.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as error:
        raise SbomError(str(error)) from error
    if len(raw) > limit:
        msg = f"{source} is over {limit} bytes, the size limit of an SBOM python-sbom reads"
        raise SbomError(msg)
    try:
        loaded = load_json(raw)
    except SbomError as error:
        msg = f"{source} {error}"
        raise SbomError(msg) from error
    if not is_document(loaded):
        msg = f"{source} is not a CycloneDX document python-sbom can render"
        raise SbomError(msg)
    return loaded


__all__ = [
    "run",  # simplint: ignore[SMP402] # the parser names it for pkgutil.resolve_name
]
