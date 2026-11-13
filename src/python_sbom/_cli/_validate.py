"""The validate subcommand: check the SBOMs of wheels, archives and standalone documents."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Protocol

from python_sbom._validate._artifact import validate  # simplint: ignore[private-import-path]  # avoid root export

if TYPE_CHECKING:
    from pathlib import Path


class _Options(Protocol):
    paths: list[Path]
    allowed_licenses: list[str] | None
    max_components: int


def run(options: _Options) -> bool:
    allowed = None if options.allowed_licenses is None else frozenset(options.allowed_licenses)
    if not (
        artifacts := sorted(
            artifact for path in options.paths for artifact in (path.glob("*.whl") if path.is_dir() else [path])
        )
    ):
        sys.stderr.write(f"no wheel found in {', '.join(map(str, options.paths))}\n")
        return False
    valid = True
    for artifact in artifacts:
        for problem in (problems := validate(artifact, allowed, options.max_components)):
            sys.stderr.write(f"SBOM invalid: {artifact.name}: {problem}\n")
        if problems:
            valid = False
        else:
            sys.stdout.write(f"SBOM in {artifact.name} is valid\n")
    return valid


__all__ = [
    "run",  # simplint: ignore[unused-export] # the parser names it for pkgutil.resolve_name
]
