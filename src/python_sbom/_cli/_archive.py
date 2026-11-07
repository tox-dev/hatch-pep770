from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath
from typing import Protocol

from python_sbom._collect._facts import collect_facts
from python_sbom._collect._revision import revision_reader
from python_sbom._formats._json import dumps
from python_sbom._generate._archive import describe_archive
from python_sbom._wheel._archive import append_member

from ._parser import BuildOptions


class _Options(BuildOptions, Protocol):
    archive: Path
    build_scripts: list[str] | None
    output: Path | None
    embed: bool


def run(options: _Options) -> bool:
    root = Path.cwd() if options.root is None else options.root
    facts = collect_facts(root, revision_reader(options.commit), path=options.build_env)
    document = describe_archive(
        root,
        options.archive,
        facts=facts,
        provider=options.content_provider,
        build_scripts=tuple(PurePosixPath(script) for script in options.build_scripts or []),
    )
    name = f"{options.archive.name}.cdx.json"
    (target := options.output or options.archive.with_name(name)).write_bytes(content := dumps(document))
    sys.stdout.write(f"wrote {target}\n")
    if options.embed:
        append_member(options.archive, name, content, facts.epoch)
        sys.stdout.write(f"wrote {name} into {options.archive.name}\n")
    return True


__all__ = [
    "run",  # simplint: ignore[SMP402] # the parser names it for pkgutil.resolve_name
]
