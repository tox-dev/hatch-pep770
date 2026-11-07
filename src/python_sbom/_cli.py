from __future__ import annotations

from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter
from pathlib import Path
from typing import TYPE_CHECKING

from ._run import run
from .version import version

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(args: Sequence[str] | None = None) -> None:
    """
    Run the command-line interface.

    :param args: command-line arguments, or ``sys.argv[1:]`` when None
    :raises SystemExit: with status 1 when a command fails

    """
    if not run(_build_parser().parse_args(args, namespace=Options())):
        raise SystemExit(1)


def _build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="python-sbom",
        description="SBOMs for Python distributions: write, convert and check the PEP 770 CycloneDX SBOMs of wheels.",
        formatter_class=RawDescriptionHelpFormatter,
        epilog=f"running {version} at {Path(__file__).parent}",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    embed = commands.add_parser(
        "embed",
        help="write the SBOM into wheels another build backend built",
        description="Write the SBOM the hatchling hook would write into wheels another build backend built, such as"
        " meson-python. Settings come from the [tool.python-sbom] table of the project's pyproject.toml.",
    )
    embed.add_argument("wheels", type=Path, nargs="+", metavar="wheel", help="wheel to rewrite in place")
    embed.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="project directory the wheels were built from (default: %(default)s)",
    )
    spdx = commands.add_parser("spdx", help="render a CycloneDX SBOM as SPDX 2.3 JSON")
    spdx.add_argument("source", type=Path, help="CycloneDX JSON file to read")
    spdx.add_argument("target", type=Path, help="SPDX JSON file to write")
    validate = commands.add_parser(
        "validate", help="validate the SBOMs in wheels", description="Needs the validate extra: python-sbom[validate]."
    )
    validate.add_argument("paths", type=Path, nargs="+", metavar="path", help="wheel, or directory holding wheels")
    validate.add_argument(
        "--allow-license",
        dest="allowed_licenses",
        action="append",
        metavar="spdx-id",
        help="SPDX license id bundled components may use; repeat it per id, leave it out to skip the license policy",
    )
    return parser


class Options(Namespace):
    """The parsed command line."""

    command: str
    """The subcommand: ``embed``, ``spdx`` or ``validate``."""
    wheels: list[Path]
    """Wheels to write an SBOM into, for ``embed``."""
    root: Path
    """Project directory the wheels were built from, for ``embed``."""
    source: Path
    """CycloneDX document to read, for ``spdx``."""
    target: Path
    """SPDX document to write, for ``spdx``."""
    paths: list[Path]
    """Wheels, or directories holding them, for ``validate``."""
    allowed_licenses: list[str] | None
    """SPDX license ids bundled components may use, for ``validate``; None skips the license policy."""


__all__ = [
    "Options",
    "main",
]
