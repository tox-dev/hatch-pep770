"""The command line's entry point: parse the arguments and run the chosen subcommand."""

from __future__ import annotations

import pkgutil
import sys
from typing import TYPE_CHECKING

from python_sbom._errors import SbomError

from ._parser import build_parser

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(args: Sequence[str] | None = None) -> None:
    options = build_parser().parse_args(args)
    try:
        succeeded = pkgutil.resolve_name(options.handler)(options)
    except SbomError as error:
        sys.stderr.write(f"python-sbom: {error}\n")
        succeeded = False
    if not succeeded:
        raise SystemExit(1)


__all__ = [
    "main",
]
