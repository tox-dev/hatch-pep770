from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath
from typing import Protocol

from python_sbom._generate._archive import archive_sbom

from ._parser import BuildOptions


class _Options(BuildOptions, Protocol):
    archive: Path
    build_scripts: list[str] | None
    output: Path | None
    embed: bool


def run(options: _Options) -> bool:
    target, embedded = archive_sbom(
        Path.cwd() if options.root is None else options.root,
        options.archive,
        provider=options.content_provider,
        commit=options.commit,
        build_env=options.build_env,
        build_scripts=tuple(PurePosixPath(script) for script in options.build_scripts or []),
        output=options.output,
        embed=options.embed,
    )
    sys.stdout.write(f"wrote {target}\n")
    if embedded is not None:
        sys.stdout.write(f"wrote {embedded} into {options.archive.name}\n")
    return True


__all__ = [
    "run",  # simplint: ignore[SMP402] # the parser names it for pkgutil.resolve_name
]
