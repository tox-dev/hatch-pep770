from __future__ import annotations

from argparse import Namespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class Options(Namespace):
    handler: Callable[[Options], bool]
    wheels: list[Path]
    root: Path | None
    commit: str | None
    build_env: list[str] | None
    content_provider: str | None
    source: Path
    target: Path
    paths: list[Path]
    allowed_licenses: list[str] | None


__all__ = [
    "Options",
]
