from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from python_sbom._collect._facts import collect_facts, default_revision
from python_sbom._collect._settings import settings_from_pyproject
from python_sbom._collect._source import read_source_tree
from python_sbom._formats._json import dumps
from python_sbom._formats._spdx import to_spdx
from python_sbom._generate._backend import BuiltWheel
from python_sbom._generate._content import ContentProvider, load_content_provider
from python_sbom._generate._pipeline import build_sbom
from python_sbom._model._inputs import Revision
from python_sbom._validate._wheel import validate_wheel
from python_sbom._wheel._archive import embed_sbom
from python_sbom.version import __version__

if TYPE_CHECKING:
    from python_sbom._collect._facts import RevisionReader

    from ._parser import Options


def embed(options: Options) -> bool:
    root = Path.cwd() if options.root is None else options.root
    settings = settings_from_pyproject(root, {})
    content, script = (
        (ContentProvider(), None)
        if (spec := options.content_provider or settings.content_provider) is None
        else load_content_provider(spec, root)
    )
    revision: RevisionReader = (
        default_revision if (commit := options.commit) is None else lambda _root: Revision(commit=commit, dirty=False)
    )
    facts = collect_facts(root, revision, options.build_env, None)
    for wheel in options.wheels:
        request = BuiltWheel(
            wheel=wheel, root=root, settings=settings, build_scripts=() if script is None else (script,)
        ).request()
        sbom = build_sbom(request, read_source_tree(request), facts, content)
        sys.stdout.write(f"wrote {embed_sbom(wheel, sbom.file_name, sbom.content, facts.epoch)} into {wheel.name}\n")
    return True


def spdx(options: Options) -> bool:
    options.target.write_bytes(dumps(to_spdx(json.loads(options.source.read_text(encoding="utf-8")), __version__)))
    return True


def validate(options: Options) -> bool:
    allowed = None if options.allowed_licenses is None else frozenset(options.allowed_licenses)
    if not (
        wheels := sorted(wheel for path in options.paths for wheel in (path.glob("*.whl") if path.is_dir() else [path]))
    ):
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
    "embed",
    "spdx",
    "validate",
]
