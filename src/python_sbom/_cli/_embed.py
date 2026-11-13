"""The embed subcommand: write the SBOM into wheels another build backend built."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Protocol

from python_sbom._generate._embed import embed_sbom  # simplint: ignore[private-import-path]  # avoid root export

from ._parser import BuildOptions


class _Options(BuildOptions, Protocol):
    wheels: list[Path]


def run(options: _Options) -> bool:
    root = Path.cwd() if options.root is None else options.root
    for wheel in options.wheels:
        written = embed_sbom(
            wheel, root, provider=options.content_provider, commit=options.commit, build_env=options.build_env
        )
        sys.stdout.write(f"wrote {written} into {wheel.name}\n")
    return True


__all__ = [
    "run",  # simplint: ignore[unused-export] # the parser names it for pkgutil.resolve_name
]
