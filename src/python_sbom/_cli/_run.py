from __future__ import annotations

import json
import sys
import tomllib
from typing import TYPE_CHECKING

from python_sbom._collect._facts import BuildFacts, git_revision
from python_sbom._collect._settings import Settings
from python_sbom._formats._json import dumps
from python_sbom._formats._spdx import to_spdx
from python_sbom._validate._checks import validate_wheel
from python_sbom._wheel._embed import BuiltWheel

if TYPE_CHECKING:
    from ._parser import Options


def run(options: Options) -> bool:
    if options.command == "embed":
        pyproject = options.root / "pyproject.toml"
        table = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("tool", {}).get("python-sbom", {})
        settings = Settings.from_table(table, f"[tool.python-sbom] of {pyproject}")
        facts = BuildFacts.collect(options.root, git_revision)
        for wheel in options.wheels:
            sys.stdout.write(f"wrote {BuiltWheel(wheel, options.root, settings).embed(facts)} into {wheel.name}\n")
        return True
    if options.command == "spdx":
        options.target.write_bytes(dumps(to_spdx(json.loads(options.source.read_text(encoding="utf-8")))))
        return True
    allowed = None if options.allowed_licenses is None else frozenset(options.allowed_licenses)
    wheels = sorted(wheel for path in options.paths for wheel in (path.glob("*.whl") if path.is_dir() else [path]))
    if not wheels:
        sys.stderr.write(f"no wheel found in {', '.join(map(str, options.paths))}\n")
        return False
    valid = True
    for wheel in wheels:
        for problem in (problems := validate_wheel(wheel, allowed)):
            sys.stderr.write(f"SBOM invalid: {wheel.name}: {problem}\n")
        if problems:
            valid = False
        else:
            sys.stdout.write(f"SBOM in {wheel.name} is valid\n")
    return valid


__all__ = [
    "run",
]
