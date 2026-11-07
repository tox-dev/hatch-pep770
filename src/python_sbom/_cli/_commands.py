from __future__ import annotations

import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from python_sbom._collect._content import load_content_provider
from python_sbom._collect._facts import collect_facts
from python_sbom._errors import SbomError
from python_sbom._formats._json import dumps
from python_sbom._formats._spdx import to_spdx
from python_sbom._generate._archive import describe_archive
from python_sbom._generate._embed import embed_sbom, revision_reader
from python_sbom._validate._artifact import validate as validate_artifact
from python_sbom._validate._document import is_document

if TYPE_CHECKING:
    from argparse import ArgumentParser, _SubParsersAction

    from ._options import Options


def add_embed(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser(
        "embed",
        help="write the SBOM into wheels another build backend built",
        description="Write the SBOM the hatchling hook writes into wheels another build backend built, such as"
        " meson-python. Options come from the [tool.python-sbom] table of the project's pyproject.toml.",
    )
    parser.set_defaults(handler=_embed)
    parser.add_argument("wheels", type=Path, nargs="+", metavar="WHEEL", help="wheel to rewrite in place")
    _add_build_options(parser)


def _embed(options: Options) -> bool:
    root = Path.cwd() if options.root is None else options.root
    content = None if options.content_provider is None else load_content_provider(options.content_provider, root)
    for wheel in options.wheels:
        written = embed_sbom(wheel, root, content=content, commit=options.commit, build_env=options.build_env)
        sys.stdout.write(f"wrote {written} into {wheel.name}\n")
    return True


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


def add_archive(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser(
        "archive",
        help="write the SBOM of a zip archive that is not a wheel, such as a zipapp",
        description="Describe a zip archive that holds the project's .dist-info at its top level, such as a zipapp:"
        " the archive's own files, the project's distribution, and every wheel it bundles, as a file or unpacked,"
        " described as the wheel's SBOM describes them. Options come from [tool.python-sbom].",
    )
    parser.set_defaults(handler=_archive)
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


def _archive(options: Options) -> bool:
    root = Path.cwd() if options.root is None else options.root
    facts = collect_facts(root, revision_reader(options.commit), path=options.build_env)
    document = describe_archive(
        root,
        options.archive,
        facts=facts,
        content=None if options.content_provider is None else load_content_provider(options.content_provider, root),
        build_scripts=tuple(PurePosixPath(script) for script in options.build_scripts or []),
    )
    name = f"{options.archive.name}.cdx.json"
    (target := options.output or options.archive.with_name(name)).write_bytes(content := dumps(document))
    sys.stdout.write(f"wrote {target}\n")
    if options.embed:
        with zipfile.ZipFile(options.archive, "a") as handle:
            if name in handle.namelist():
                msg = f"{options.archive.name} already holds {name}"
                raise SbomError(msg)
            # a fixed time and Unix attributes, so the archive's bytes are the same whichever system adds the entry
            entry = zipfile.ZipInfo(name, datetime.fromtimestamp(max(facts.epoch, 315532800), tz=UTC).timetuple()[:6])
            entry.create_system, entry.external_attr = 3, 0o644 << 16
            handle.writestr(entry, content)
        sys.stdout.write(f"wrote {name} into {options.archive.name}\n")
    return True


def add_spdx(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser("spdx", help="render a CycloneDX SBOM as SPDX 2.3 JSON")
    parser.set_defaults(handler=_spdx)
    parser.add_argument("source", type=Path, metavar="SOURCE", help="CycloneDX JSON file to read")
    parser.add_argument("target", type=Path, metavar="TARGET", help="SPDX JSON file to write")


def _spdx(options: Options) -> bool:
    if not is_document(loaded := json.loads(options.source.read_text(encoding="utf-8"))):
        msg = f"{options.source} is not a CycloneDX document python-sbom can render"
        raise SbomError(msg)
    try:
        rendered = to_spdx(loaded)
    except (KeyError, TypeError) as error:
        # the CLI renders without the schema check, which needs the validate extra
        msg = f"{options.source} is not a CycloneDX document python-sbom can render: {error!r}"
        raise SbomError(msg) from error
    # bytes, so the line endings are the same on every operating system
    options.target.write_bytes(rendered.encode())
    return True


def add_validate(commands: _SubParsersAction[ArgumentParser]) -> None:
    parser = commands.add_parser(
        "validate",
        help="validate the SBOMs in wheels and archives",
        description="Check every CycloneDX SBOM a wheel or archive holds against the CycloneDX 1.6 schema; for one"
        " python-sbom wrote, also its serial number, references, SPDX rendering and, with --allow-license, the licenses"
        " of what it ships. Needs the validate extra: python-sbom[validate].",
    )
    parser.set_defaults(handler=_validate)
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


def _validate(options: Options) -> bool:
    allowed = None if options.allowed_licenses is None else frozenset(options.allowed_licenses)
    if not (
        artifacts := sorted(
            artifact for path in options.paths for artifact in (path.glob("*.whl") if path.is_dir() else [path])
        )
    ):
        sys.stderr.write(f"no wheel found in {', '.join(map(str, options.paths))}\n")
        return False
    valid = True
    for artifact in artifacts:
        for problem in (problems := validate_artifact(artifact, allowed)):
            sys.stderr.write(f"SBOM invalid: {artifact.name}: {problem}\n")
        if problems:
            valid = False
        else:
            sys.stdout.write(f"SBOM in {artifact.name} is valid\n")
    return valid


__all__ = [
    "add_archive",
    "add_embed",
    "add_spdx",
    "add_validate",
]
