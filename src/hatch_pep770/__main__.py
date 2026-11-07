"""Command line: render a CycloneDX SBOM as SPDX, or validate the SBOMs in built wheels."""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from .spdx import to_spdx


class _Options(Namespace):
    command: str
    source: Path
    target: Path
    paths: list[Path]
    allow_license: list[str] | None


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(prog="hatch-pep770", description="Work with the PEP 770 SBOMs hatch-pep770 writes.")
    commands = parser.add_subparsers(dest="command", required=True)
    spdx = commands.add_parser("spdx", help="render a CycloneDX SBOM as SPDX 2.3 JSON")
    spdx.add_argument("source", type=Path, help="the CycloneDX JSON file to read")
    spdx.add_argument("target", type=Path, help="the SPDX JSON file to write")
    validate = commands.add_parser(
        "validate", help="validate the SBOMs in wheels, needs the validate extra: hatch-pep770[validate]"
    )
    validate.add_argument("paths", type=Path, nargs="+", help="wheel files, or directories holding them")
    validate.add_argument(
        "--allow-license",
        action="append",
        metavar="SPDX-ID",
        help="SPDX license id bundled components may use; repeat it per id, leave it out to skip the license policy",
    )
    options = parser.parse_args(argv, namespace=_Options())
    if options.command == "spdx":
        bom = json.loads(options.source.read_text(encoding="utf-8"))
        options.target.write_bytes(f"{json.dumps(to_spdx(bom), indent=2)}\n".encode())
        return 0
    # validate pulls in the optional extra, so the spdx command works without it
    from .validate import wheel_problems  # ruff: ignore[import-outside-top-level]

    allowed = None if options.allow_license is None else frozenset(options.allow_license)
    wheels = sorted(wheel for path in options.paths for wheel in (path.glob("*.whl") if path.is_dir() else [path]))
    if not wheels:
        sys.stderr.write(f"no wheel found in {', '.join(map(str, options.paths))}\n")
        return 1
    failed = False
    for wheel in wheels:
        for problem in (problems := wheel_problems(wheel, allowed)):
            sys.stderr.write(f"SBOM invalid: {wheel.name}: {problem}\n")
        if problems:
            failed = True
        else:
            sys.stdout.write(f"SBOM in {wheel.name} is valid\n")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
