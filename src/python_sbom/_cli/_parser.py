from __future__ import annotations

from argparse import ArgumentParser

from python_sbom.version import __version__

from ._commands import add_archive, add_embed, add_spdx, add_validate


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="python-sbom", description="Write, convert and check the CycloneDX SBOMs of wheels.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(required=True)
    for add in (add_embed, add_archive, add_spdx, add_validate):
        add(commands)
    return parser


__all__ = [
    "build_parser",
]
