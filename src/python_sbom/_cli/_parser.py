from __future__ import annotations

from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import TYPE_CHECKING

from ._commands import embed, spdx, validate

if TYPE_CHECKING:
    from collections.abc import Callable


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


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="python-sbom", description="Write, convert and check the CycloneDX SBOMs of wheels.")
    commands = parser.add_subparsers(required=True)
    embed_parser = commands.add_parser(
        "embed",
        help="write the SBOM into wheels another build backend built",
        description="Write the SBOM the hatchling hook writes into wheels another build backend built, such as"
        " meson-python. Options come from the [tool.python-sbom] table of the project's pyproject.toml.",
    )
    embed_parser.set_defaults(handler=embed)
    embed_parser.add_argument("wheels", type=Path, nargs="+", metavar="wheel", help="wheel to rewrite in place")
    embed_parser.add_argument(
        "--root", type=Path, help="project directory the wheels were built from (default: current directory)"
    )
    embed_parser.add_argument("--commit", help="source revision to record, for a wheel built from an sdist")
    embed_parser.add_argument(
        "--build-env",
        action="append",
        metavar="dir",
        help="site-packages directory of the environment that built the wheels; repeat it per directory"
        " (default: this interpreter's)",
    )
    embed_parser.add_argument(
        "--content-provider",
        metavar="module:attribute",
        help="content provider, overriding the content-provider option",
    )
    spdx_parser = commands.add_parser("spdx", help="render a CycloneDX SBOM as SPDX 2.3 JSON")
    spdx_parser.set_defaults(handler=spdx)
    spdx_parser.add_argument("source", type=Path, help="CycloneDX JSON file to read")
    spdx_parser.add_argument("target", type=Path, help="SPDX JSON file to write")
    validate_parser = commands.add_parser(
        "validate", help="validate the SBOMs in wheels", description="Needs the validate extra: python-sbom[validate]."
    )
    validate_parser.set_defaults(handler=validate)
    validate_parser.add_argument(
        "paths", type=Path, nargs="+", metavar="path", help="wheel, or directory holding wheels"
    )
    validate_parser.add_argument(
        "--allow-license",
        dest="allowed_licenses",
        action="append",
        metavar="spdx-id",
        help="SPDX license id bundled components may use; repeat it per id, leave it out to skip the license policy",
    )
    return parser


__all__ = [
    "Options",
    "build_parser",
]
