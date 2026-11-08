from __future__ import annotations

from argparse import ArgumentParser, ArgumentTypeError, _SubParsersAction
from pathlib import Path
from typing import Protocol

# the limits module imports nothing, so --help and --version load none of validation
from python_sbom._validate._limits import MAX_COMPONENTS
from python_sbom.version import __version__


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="python-sbom", description="Write, convert and check the CycloneDX SBOMs of wheels.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(required=True)
    _add_embed(commands)
    _add_archive(commands)
    _add_spdx(commands)
    _add_validate(commands)
    return parser


def _add_embed(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser(
        "embed",
        help="write the SBOM into wheels another build backend built",
        description="Write the SBOM the hatchling hook writes into wheels another build backend built, such as"
        " meson-python. Options come from the [tool.python-sbom] table of the project's pyproject.toml.",
    )
    # a name, not the function, so each command imports only what it runs and --help imports none of it
    parser.set_defaults(handler="python_sbom._cli._embed:run")
    parser.add_argument("wheels", type=Path, nargs="+", metavar="WHEEL", help="wheel to rewrite in place")
    _add_build_options(parser)


def _add_build_options(parser: ArgumentParser) -> None:
    parser.add_argument(
        "--root", type=Path, metavar="DIR", help="project directory of the artifact (default: current directory)"
    )
    parser.add_argument(
        "--commit", metavar="SHA", help="source revision to record, for an artifact built from an sdist"
    )
    parser.add_argument(
        "--build-env",
        action="append",
        metavar="DIR",
        help="site-packages directory of the environment that built the artifact; repeat it per directory"
        " (default: this interpreter's)",
    )
    parser.add_argument(
        "--content-provider",
        metavar="MODULE:ATTRIBUTE",
        help="content provider, overriding the content-provider option",
    )


def _add_archive(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser(
        "archive",
        help="write the SBOM of a zip archive that is not a wheel, such as a zipapp",
        description="Describe a zip archive that holds the project's .dist-info at its top level, such as a zipapp:"
        " the archive's own files, the project's distribution, and every wheel it bundles, as a file or unpacked,"
        " described as the wheel's SBOM describes them. Options come from [tool.python-sbom].",
    )
    parser.set_defaults(handler="python_sbom._cli._archive:run")
    parser.add_argument("archive", type=Path, metavar="ARCHIVE", help="archive to describe")
    _add_build_options(parser)
    parser.add_argument(
        "--build-script",
        dest="build_scripts",
        action="append",
        metavar="PATH",
        help="script, relative to the project, that built the archive; repeat it per script",
    )
    parser.add_argument(
        "--output", type=Path, metavar="FILE", help="SBOM file to write (default: <archive>.cdx.json next to it)"
    )
    parser.add_argument(
        "--embed", action="store_true", help="also add the SBOM to the archive, at its top level as <archive>.cdx.json"
    )


def _add_spdx(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser(
        "spdx",
        help="render a CycloneDX SBOM as SPDX 2.3 JSON",
        description="Render a CycloneDX JSON SBOM, such as one python-sbom wrote, as an SPDX 2.3 JSON document. It"
        " checks only the fields the rendering reads, so it needs no extra; python-sbom validate checks the whole"
        " document.",
    )
    parser.set_defaults(handler="python_sbom._cli._spdx:run")
    parser.add_argument("source", type=Path, metavar="SOURCE", help="CycloneDX JSON file to read")
    parser.add_argument("target", type=Path, metavar="TARGET", help="SPDX JSON file to write")


def _add_validate(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser(
        "validate",
        help="validate the SBOMs in wheels and archives",
        description="Check every CycloneDX SBOM a wheel or archive holds against the CycloneDX 1.6 schema; for one"
        " python-sbom wrote, also its serial number, references, SPDX rendering and, with --allow-license, the licenses"
        " of what it ships. Needs the validate extra: python-sbom[validate].",
    )
    parser.set_defaults(handler="python_sbom._cli._validate:run")
    parser.add_argument(
        "paths", type=Path, nargs="+", metavar="PATH", help="wheel, archive, or directory holding wheels"
    )
    parser.add_argument(
        "--allow-license",
        dest="allowed_licenses",
        action="append",
        metavar="SPDX-ID",
        help="SPDX license id shipped components may use; repeat it per id, leave it out to skip the license policy",
    )
    parser.add_argument(
        "--max-components",
        type=_positive_int,
        default=MAX_COMPONENTS,
        metavar="N",
        help="reject an SBOM listing more than N components, nested ones included, or larger than 1 MiB plus 1 KiB per"
        " component, without checking it further, which bounds the work an untrusted SBOM can ask for (default:"
        f" {MAX_COMPONENTS})",
    )


def _positive_int(text: str) -> int:
    # argparse reports the error through parser.error, with the usage, like any other bad argument
    if text.isdecimal() and (number := int(text)) > 0:
        return number
    msg = f"must be a positive integer, got {text!r}"
    raise ArgumentTypeError(msg)


class BuildOptions(Protocol):
    root: Path | None
    commit: str | None
    build_env: list[str] | None
    content_provider: str | None


__all__ = [
    "BuildOptions",
    "build_parser",
]
