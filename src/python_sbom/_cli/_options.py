from __future__ import annotations

from argparse import Namespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class Options(Namespace):
    # each subcommand sets only its own fields; its handler reads only those
    handler: Callable[[Options], bool]
    wheels: list[Path]
    archive: Path
    root: Path | None
    commit: str | None
    build_env: list[str] | None
    build_scripts: list[str] | None
    content_provider: str | None
    output: Path | None
    embed: bool
    source: Path
    target: Path
    paths: list[Path]
    allowed_licenses: list[str] | None
    max_components: int


__all__ = [
    "Options",
]
