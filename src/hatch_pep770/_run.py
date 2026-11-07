from __future__ import annotations

import json
import sys
import tomllib
from typing import TYPE_CHECKING

from ._embed import embed
from ._project import Project
from ._spdx import to_spdx
from ._validate import validate_wheel

if TYPE_CHECKING:
    from ._cli import Options


def run(options: Options) -> bool:
    if options.command == "embed":
        pyproject = options.root / "pyproject.toml"
        table = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("tool", {}).get("hatch-pep770", {})
        project = Project.from_table(table, root=options.root, where=f"[tool.hatch-pep770] of {pyproject}")
        for wheel in options.wheels:
            sys.stdout.write(f"wrote {embed(wheel, project)} into {wheel.name}\n")
        return True
    if options.command == "spdx":
        bom = json.loads(options.source.read_text(encoding="utf-8"))
        options.target.write_bytes(f"{json.dumps(to_spdx(bom), indent=2)}\n".encode())
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
